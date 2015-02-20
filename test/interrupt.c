
#define CAUSE   ((int*) 0x210c)
#define EPC     ((int*) 0x2108)
#define INTENBL ((int*) 0x2104)
#define HANDLER ((int*) 0x2100)

#define SERIAL ((char*) 0x2000)

#define IRQ_TIMER    1
#define IRQ_SERIAL   2
#define IRQ_SYSENTER 3

int timer_count = 0;

void trap()
{
    switch (*CAUSE) {
        case IRQ_TIMER:
            timer_count++;
            if (timer_count > 50 == 0) {
                *SERIAL = 'T';
            }
            if (timer_count > 100) {
                __asm ("sysenter\n");
                timer_count = 0;
            }
            break;
        case IRQ_SERIAL:
            *SERIAL = 'K';
            *SERIAL = *SERIAL;
            break;

        case IRQ_SYSENTER:
            *SERIAL = 'S';
            break;
        default:
            *SERIAL = 'E';
    }
    *(int*)0x2108 = *(int*)0x2108 - 4; // GAIA processors store interrupted address + 4, so we have to do some math.
    __asm ("sysexit\n");
}

int main()
{
    *HANDLER = (int) trap;
    *INTENBL = 1;

    for (;;)1+1;
}
