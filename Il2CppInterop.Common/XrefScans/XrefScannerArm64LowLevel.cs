using System;
using System.Collections.Generic;
using Disarm;

namespace Il2CppInterop.Common.XrefScans;

/// <summary>
/// arm64 (AArch64) parallel of <see cref="XrefScannerLowLevel"/>. The original
/// scanner uses Iced (x86/x64-only); on arm64 the Iced decoder treats arm64
/// bytes as nonsense, never emits the right control-flow mnemonics, and every
/// JumpTargets enumerable comes back empty. This module re-implements the
/// same yield semantics with Disarm — a pure-managed arm64 disassembler that
/// Cpp2IL already ships transitively, so we don't pull in a new native dep.
///
/// <para>Yielded by <see cref="JumpTargets"/>:</para>
/// <list type="bullet">
///   <item><description>Unconditional <c>B &lt;label&gt;</c> targets (one per branch). The
///   first such branch terminates the walk, mirroring the Iced behaviour.</description></item>
///   <item><description><c>BL &lt;label&gt;</c> call targets — these are the "calls" the
///   x86 scanner treats as <c>FlowControl.Call</c>.</description></item>
/// </list>
///
/// <para>The walk stops at <c>RET</c> / <c>ERET</c> / <c>BRK</c> (unless
/// <c>ignoreRetn</c> is set, in which case <c>RET</c> alone is ignored —
/// matching the Iced override semantics).</para>
///
/// <para>arm64 has no near-jump-short distinction; <c>B/BL</c> always have a
/// ±128 MiB range, which is what the x86 path "hopes" for via
/// <c>!IsJmpShort</c>. So the arm64 path always yields the target.</para>
/// </summary>
internal static class XrefScannerArm64LowLevel
{
    // arm64 instructions are all 4 bytes; 1 KiB of code = 256 instructions.
    // The existing x86 default lengthLimit is 1000 bytes — we mirror that as
    // a 256-instruction (= 1024-byte) cap.
    private const int DefaultLengthLimit = 1024;

    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn)
    {
        return JumpTargetsImpl(codeStart, DefaultLengthLimit, ignoreRetn);
    }

    public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr codeStart)
    {
        // x86 path uses 1 MiB; arm64 path mirrors that.
        return CallAndIndirectTargetsImpl(codeStart, 1024 * 1024);
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(IntPtr codeStart, int lengthLimit, bool ignoreRetn)
    {
        if (codeStart == IntPtr.Zero) yield break;
        var firstFlowControl = true;
        foreach (Arm64Instruction instr in EnumerateArm64(codeStart, lengthLimit))
        {
            switch (instr.Mnemonic)
            {
                case Arm64Mnemonic.RET:
                case Arm64Mnemonic.ERET:
                    if (!ignoreRetn) yield break;
                    break;

                case Arm64Mnemonic.BRK:
                case Arm64Mnemonic.HLT:
                    // Treat traps as the arm64 analogue of x86's INT3 padding —
                    // anything past here is not part of the live function body.
                    yield break;

                case Arm64Mnemonic.B:
                {
                    // Unconditional branch: yield the target. If this is the
                    // first flow-control instruction we see, stop walking (the
                    // x86 path does the same for `jmp`).
                    if (TryGetPcRelativeTarget(in instr, out IntPtr target))
                        yield return target;
                    if (firstFlowControl) yield break;
                    break;
                }

                case Arm64Mnemonic.BL:
                {
                    // Call: always yield the target, keep walking.
                    if (TryGetPcRelativeTarget(in instr, out IntPtr target))
                        yield return target;
                    break;
                }

                default:
                    // Conditional branches (B.cond), TBZ/TBNZ, CBZ/CBNZ, BR/BLR
                    // (register-indirect — we can't recover the target without
                    // simulating register state) flow on. Just mark
                    // firstFlowControl = false so a subsequent unconditional
                    // branch doesn't terminate the walk too early.
                    if (instr.MnemonicCategory == Arm64MnemonicCategory.ConditionalBranch
                        || instr.MnemonicCategory == Arm64MnemonicCategory.Branch
                        || instr.MnemonicCategory == Arm64MnemonicCategory.Return)
                    {
                        firstFlowControl = false;
                    }
                    break;
            }

            if (instr.MnemonicCategory == Arm64MnemonicCategory.Branch
                || instr.MnemonicCategory == Arm64MnemonicCategory.ConditionalBranch
                || instr.MnemonicCategory == Arm64MnemonicCategory.Return)
            {
                firstFlowControl = false;
            }
        }
    }

    private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(IntPtr codeStart, int lengthLimit)
    {
        if (codeStart == IntPtr.Zero) yield break;
        foreach (Arm64Instruction instr in EnumerateArm64(codeStart, lengthLimit))
        {
            switch (instr.Mnemonic)
            {
                case Arm64Mnemonic.RET:
                case Arm64Mnemonic.ERET:
                    yield break;

                case Arm64Mnemonic.BRK:
                case Arm64Mnemonic.HLT:
                case Arm64Mnemonic.SVC:
                    yield break;

                case Arm64Mnemonic.B:
                case Arm64Mnemonic.BL:
                {
                    if (TryGetPcRelativeTarget(in instr, out IntPtr target))
                        yield return target;
                    break;
                }

                case Arm64Mnemonic.ADRP:
                case Arm64Mnemonic.ADR:
                {
                    // arm64 analogue of the x86 LEA-RIP-relative case the x86
                    // scanner uses to discover global addresses. Disarm hands
                    // us a relative immediate; we resolve it against the
                    // instruction's address (with ADRP's bottom-12-bit zero).
                    if (TryGetLoadAddressTarget(in instr, out IntPtr target))
                        yield return target;
                    break;
                }
            }
        }
    }

    private static bool TryGetPcRelativeTarget(in Arm64Instruction instr, out IntPtr target)
    {
        // Disarm encodes B / BL targets in Op0Imm as a sign-extended *relative*
        // byte offset (imm26 << 2), NOT the absolute resolved VA — verified
        // against Disarm.InternalDisassembly.Branches.UnconditionalBranchImmediate.
        // Resolve to absolute by adding the instruction's address.
        if (instr.Op0Kind == Arm64OperandKind.ImmediatePcRelative)
        {
            long absolute = unchecked((long)instr.Address) + instr.Op0Imm;
            if (absolute != 0)
            {
                target = new IntPtr(absolute);
                return true;
            }
        }
        target = default;
        return false;
    }

    /// <summary>
    /// Resolve an ADR or ADRP load-address. ADR adds a sign-extended 21-bit
    /// immediate to PC; ADRP zeros the bottom 12 bits of PC and adds a
    /// 12-bit-shifted immediate. Disarm hands us the corrected immediate in
    /// Op1Imm but leaves the PC composition to the caller.
    /// </summary>
    private static bool TryGetLoadAddressTarget(in Arm64Instruction instr, out IntPtr target)
    {
        if (instr.Mnemonic == Arm64Mnemonic.ADR)
        {
            long absolute = unchecked((long)instr.Address) + instr.Op1Imm;
            target = new IntPtr(absolute);
            return target != IntPtr.Zero;
        }
        if (instr.Mnemonic == Arm64Mnemonic.ADRP)
        {
            long pcPage = unchecked((long)instr.Address) & ~0xFFFL;
            long absolute = pcPage + instr.Op1Imm;
            target = new IntPtr(absolute);
            return target != IntPtr.Zero;
        }
        target = default;
        return false;
    }

    /// <summary>
    /// Stream Disarm-decoded instructions starting at <paramref name="codeStart"/>,
    /// reading at most <paramref name="byteLimit"/> bytes. Reads four bytes at a
    /// time so a function near the end of a mapped page (or near the end of
    /// the .text section) doesn't trip an AccessViolationException — the
    /// 1 MiB budget for CallAndIndirectTargets routinely overshoots mapped
    /// memory, and a single bulk Marshal.Copy across that range would fault.
    /// arm64 instructions are strictly 4-byte aligned, so per-instruction
    /// reads are exact.
    /// </summary>
    private static IEnumerable<Arm64Instruction> EnumerateArm64(IntPtr codeStart, int byteLimit)
    {
        int aligned = byteLimit & ~3;
        // Reused 4-byte buffer; Disarm's bytes-overload decodes a single
        // instruction from one such buffer.
        byte[] one = new byte[4];
        for (int offset = 0; offset < aligned; offset += 4)
        {
            int word;
            try
            {
                word = System.Runtime.InteropServices.Marshal.ReadInt32(codeStart, offset);
            }
            catch (System.AccessViolationException)
            {
                // Walked off a mapped page (.text section ended, or hit a
                // guard page). Stop cleanly — the consumer's state machine
                // will handle the truncated stream.
                yield break;
            }

            one[0] = (byte)(word & 0xFF);
            one[1] = (byte)((word >> 8) & 0xFF);
            one[2] = (byte)((word >> 16) & 0xFF);
            one[3] = (byte)((word >> 24) & 0xFF);

            Arm64Instruction instr;
            try
            {
                IEnumerable<Arm64Instruction> stream = Disassembler.Disassemble(
                    one,
                    (ulong)codeStart.ToInt64() + (uint)offset,
                    Disassembler.Options.IgnoreErrors);
                using IEnumerator<Arm64Instruction> en = stream.GetEnumerator();
                if (!en.MoveNext()) yield break;
                instr = en.Current;
            }
            catch
            {
                // Disarm couldn't decode (unsupported instruction, etc.). Skip
                // forward to the next 4-byte boundary; an undecodable
                // instruction in the middle of a function is rare but the
                // walk shouldn't be aborted by it.
                continue;
            }
            yield return instr;
        }
    }
}
