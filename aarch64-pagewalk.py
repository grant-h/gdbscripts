import math
import gdb

KERNEL_BASE = 0xffffffffc0000000

class SwitchEL(gdb.Command):
    def __init__(self):
        super(SwitchEL, self).__init__("switchel", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = list(filter(lambda x: x.strip() != "", arg.split(" ")))
        argc = len(argv)

        CPSR = int(gdb.parse_and_eval('$cpsr')) & 0xffffffff
        CurrentEL = int((CPSR >> 2) & 0b11)

        if argc < 1:
            print('$cpsr = 0x%x (EL%d)' % (CPSR, CurrentEL))
            return
        else:
            try:
                target_el = int(argv[0])

                if target_el < 0 or target_el > 3:
                    print("Invalid argument (ELx>=0 && ELx<=3)")
                    return

            except ValueError:
                print("Invalid argument (ELx integer required)")
                return

            if target_el != CurrentEL:
                # clear EL
                CPSR = CPSR & ~(0b11 << 2)
                # set desired EL
                CPSR |= target_el << 2
                gdb.parse_and_eval('$cpsr = 0x%08x' % CPSR)
                print('Moving to EL%d' % (target_el))
            else:
                print('Already at EL%d' % (target_el))

            # reload CPSR
            CPSR = int(gdb.parse_and_eval('$cpsr')) & 0xffffffff
            CurrentEL = int((CPSR >> 2) & 0b11)

        print('$cpsr = 0x%x' % (CPSR))

class PageWalk(gdb.Command):
    def __init__(self):
        self.print_flags = False
        self.print_each_level = False

        super(PageWalk, self).__init__("pagewalk", gdb.COMMAND_DATA)

    def loadq(self, addr):
        v = gdb.parse_and_eval('*(unsigned long long*)(%s)' % addr)
        return int(v)

    def format_entry(self, entry, S2):
        if S2:
            XN = (entry >> 53) & 0b11
            S2AP = (entry >> 6) & 0b11
            A = (entry >> 10) & 0b1
            PhyAddr = entry & 0xfffffffff000

            flags = []

            # Stage 2 - D4-2160
            if XN == 0:
                pass
            elif XN == 1:
                flags += ['PXN']
            elif XN == 2:
                flags += ['UXN','PXN']
            elif XN == 3:
                flags += ['UXN']

            if not A:
                flags += ['!ACC']

            if S2AP == 0:
                flags += ['ELx/NONE']
            elif S2AP == 1:
                flags += ['ELx/RO']
            elif S2AP == 2:
                flags += ['ELx/WO']
            elif S2AP == 3:
                flags += ['ELx/RW']

            flags = " ".join(flags)

            if self.print_flags:
                return "0x%016lx [%s]" % (entry, flags)
            else:
                return "0x%016lx [%s]" % (PhyAddr, flags)
        else:
            XN = (entry >> 53) & 0b11
            AP = (entry >> 6) & 0b11
            NS = (entry >> 5) & 0b1
            A = (entry >> 10) & 0b1
            PhyAddr = entry & 0xfffffffff000

            flags = []

            # D4-2151
            if XN & 1:
                flags += ['PXN']
            if XN & 2:
                flags += ['UXN']

            if NS:
                flags += ['NS']

            if not A:
                flags += ['!ACC']

            if AP == 0:
                flags += ['EL1/RW']
            elif AP == 1:
                flags += ['ELx/RW']
            elif AP == 2:
                flags += ['EL1/RO']
            elif AP == 3:
                flags += ['ELx/RO']

            flags = " ".join(flags)

            if self.print_flags:
                return "0x%016lx [%s]" % (entry, flags)
            else:
                return "0x%016lx [%s]" % (PhyAddr, flags)

    def print_table(self, pt_pa, granule_bits, region_sz, pt_va_base=0, upper_region=False):
        # assuming that the PA range is 47:0 (48-bits)
        stride = granule_bits - 3
        entries_per_table = 2**(stride)
        # round up to the nearest level
        levels = int(math.ceil((64.0 - region_sz - granule_bits)/stride))

        print("Entries/table: %d" % entries_per_table)
        print("Levels: %d" % levels)

        next_lookups = []

        # Table addresses are physical. From the perspective of GDB
        # and depending on if the MMU is enabled, we need to find the
        # corresponding virtual address for the page tables
        tables = [[0, pt_pa]]
        next_tables = []

        if upper_region:
            tables[0][0] = 0xffff000000000000

        # coalesce adjacent entries
        mappings = []

        for level in range(levels):
            if len(tables) == 0:
                break

            last_level = (level+1) == levels

            # Taken straight from D4.2.3 - Memory translation granule size
            x = levels - (level+1) + 3
            lbit = min(47, (x-3)*(stride) + 2*granule_bits-4)
            rbit = granule_bits + (x-3)*(stride)
            bitwidth = lbit - rbit + 1

            if self.print_each_level:
                print("----- LEVEL %d -----" % level)

            for va, table_addr in tables:
                for entry_no in range(entries_per_table):
                    # each entry is 8 bytes
                    entry = self.loadq(pt_va_base + table_addr+entry_no*8)
                    new_va = va | (entry_no << rbit)

                    # next table entry
                    if (entry & 0b11) == 3:
                        if last_level:
                            if self.print_each_level:
                                print("%016lx: %s" % (new_va, self.format_entry(entry, False)))
                            mappings += [[new_va, self.format_entry(entry, False)]]
                        else:
                            if self.print_each_level:
                                print("%016lx: %016lx" % (new_va, entry))
                            next_tables += [[new_va, (entry & 0xfffffff000)]]
                    # block entry
                    elif (entry & 0b11) == 1:
                        if self.print_each_level:
                            print("%016lx: %s" % (new_va, self.format_entry(entry, False)))
                        mappings += [[new_va, self.format_entry(entry, False)]]

            tables = next_tables
            next_tables = []

        if len(mappings):
            for m in mappings:
                print("%016lx: %s" % (m[0], m[1]))
        else:
            print("No virtual mappings found")

    def invoke(self, arg, from_tty):
        argv = list(filter(lambda x: x.strip() != "", arg.split(" ")))
        argc = len(argv)

        SAVED_CPSR = 0
        CPSR = int(gdb.parse_and_eval('$cpsr')) & 0xffffffff
        CurrentEL = int((CPSR >> 2) & 0b11)

        if argc == 1:
            try:
                target_el = int(argv[0])

                if target_el < 1 or target_el > 3:
                    print("Invalid argument (ELx>=1 && ELx<=3)")
                    return

                if target_el != CurrentEL:
                    SAVED_CPSR = CPSR

                    # clear EL
                    CPSR = CPSR & ~(0b11 << 2)
                    # set desired EL
                    CPSR |= target_el << 2
                    gdb.parse_and_eval('$cpsr = 0x%08x' % CPSR)
                    print('Moving to EL%d' % (target_el))

            except ValueError:
                print("Invalid argument (ELx integer required)")
                return

            # reload CPSR
            CPSR = int(gdb.parse_and_eval('$cpsr')) & 0xffffffff
            CurrentEL = int((CPSR >> 2) & 0b11)

        print('CPSR: EL%d' % (CurrentEL))

        try:
            if CurrentEL < 1:
                print('No paging in EL0')
                return
            elif CurrentEL == 1:
                TTBR0_EL1 = int(gdb.parse_and_eval('$TTBR0_EL1'))
                TTBR1_EL1 = int(gdb.parse_and_eval('$TTBR1_EL1'))
                TCR_EL1 = int(gdb.parse_and_eval('$TCR_EL1'))

                # Translation 0 Region Size (usermode)
                T0SZ = TCR_EL1 & 0b111111
                # Translation 1 Region Size (kernel)
                T1SZ = (TCR_EL1 >> 16) & 0b111111
                # Translation 0 Granule Size (user)
                TG0 = (TCR_EL1 >> 14) & 0b11
                # Translation 1 Granule Size (kernel)
                TG1 = (TCR_EL1 >> 30) & 0b11
                IPS = (TCR_EL1 >> 32) & 0b111

                print('IPA Size: %d-bits' % (32+4*IPS))

                if TG0 == 0b00:
                    TG0_BITS = 12
                elif TG0 == 0b01:
                    TG0_BITS = 16
                elif TG0 == 0b10:
                    TG0_BITS = 14
                else:
                    print("TG0 reserved")

                if TG1 == 0b01:
                    TG1_BITS = 14
                elif TG1 == 0b10:
                    TG1_BITS = 12
                elif TG1 == 0b11:
                    TG1_BITS = 16
                else:
                    print("TG1 reserved")

                print('EL1 Kernel Region Min: 0x%016lx' % (2**64 - 2**(64-T1SZ)))
                print('EL1 Kernel Page Size: %dKB' % (2**TG1_BITS >> 10))
                print('EL1 User Region Max:   0x%016lx' % (2**(64-T0SZ)-1))
                print('EL1 User Page Size: %dKB' % (2**TG0_BITS >> 10))

                print('User Mode Page Tables')
                self.print_table(TTBR0_EL1, TG0_BITS, T0SZ, pt_va_base=KERNEL_BASE)

                print()
                print('Kernel Mode Page Tables')
                self.print_table(TTBR1_EL1, TG1_BITS, T1SZ, pt_va_base=KERNEL_BASE,
                        upper_region=True)
            elif CurrentEL == 2:
                VTCR_EL2 = int(gdb.parse_and_eval('$VTCR_EL2'))
                VTTBR_EL2 = int(gdb.parse_and_eval('$VTTBR_EL2'))

                # Translation 0 Region Size (hypervisor
                T0SZ = VTCR_EL2 & 0b111111
                PA = (VTCR_EL2 >> 16) & 0b11
                TG0 = (VTCR_EL2 >> 14) & 0b11
                SL0 = (VTCR_EL2 >> 6) & 0b11

                if TG0 == 0b00:
                    TG0_BITS = 12
                elif TG0 == 0b01:
                    TG0_BITS = 16
                elif TG0 == 0b10:
                    TG0_BITS = 14
                else:
                    print("TG0 reserved")

                print('PA Size: %d-bits' % (32+4*PA))
                print('EL2 Starting Level: %d' % (SL0))
                print('EL2 Region Max: 0x%016lx' % (2**(64-T0SZ)-1))
                print('EL2 Page Size: %dKB' % (2**TG0_BITS >> 10))

                self.print_table(VTTBR_EL2, TG0_BITS, T0SZ)
            elif CurrentEL == 3:
                TTBR0_EL3 = int(gdb.parse_and_eval('$TTBR0_EL3'))
                TCR_EL3 = int(gdb.parse_and_eval('$TCR_EL3'))

                # Translation 0 Region Size (hypervisor
                T0SZ = TCR_EL3 & 0b111111
                PA = (TCR_EL3 >> 16) & 0b11
                TG0 = (TCR_EL3 >> 14) & 0b11

                if TG0 == 0b00:
                    TG0_BITS = 12
                elif TG0 == 0b01:
                    TG0_BITS = 16
                elif TG0 == 0b10:
                    TG0_BITS = 14
                else:
                    print("TG0 reserved")

                print('PA Size: %d-bits' % (32+4*PA))
                print('EL3 Region Max: 0x%016lx' % (2**(64-T0SZ)-1))
                print('EL3 Page Size: %dKB' % (2**TG0_BITS >> 10))

                self.print_table(TTBR0_EL3, TG0_BITS, T0SZ)
        except KeyboardInterrupt:
            pass

        if SAVED_CPSR:
            gdb.parse_and_eval('$cpsr = 0x%08x' % SAVED_CPSR)
            SavedEL = (SAVED_CPSR >> 2) & 0b11
            print('Moving back to EL%d' % (SavedEL))

PageWalk()
SwitchEL()
