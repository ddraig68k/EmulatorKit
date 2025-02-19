/*
 *	Y Ddraig 68000 computer
 *
 *	68000 @ 10MHz
 *	68230 PIT
 *	68681 DUART
 *	1MB SRAM
 *  8MB DRAM
 *  512KB EEPROM
 *
 *	Console on DUART port 0
 *
 *	TODO:
 *
 *
 *	Memory map (PAL)
 *  000000-0FFFFF SRAM
 *  100000-8FFFFF DRAM
 *  A00000-AFFFFF Expansion slot 1 data
 *  B00000-BFFFFF Expansion slot 2 data
 *  C00000-CFFFFF Expansion slot 3 data
 *  D00000-DFFFFF Expansion slot 4 data
 *  F7F000-F7F0FF 68681 DUART
 *  F7F100-F7F1FF 68230 PIT
 *  F7F200-F7F2FF VT82C42 Keyboard controller
 *  F7F300-F7F3FF IDE Interface
 *  F7F400-F7F4FF RTC-72421 Real time clock
 *  F7F500-F7F5FF Expansion slot 1 registers
 *  F7F600-F7F6FF Expansion slot 2 registers
 *  F7F700-F7F7FF Expansion slot 3 registers
 *  F7F800-F7F8FF Expansion slot 4 registers
 *  F80000-FFFFFF ROM
 *
 *	As is typical the ROM appears low for the first 4 read cycles then the counter
 *	maps it high only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <m68k.h>
#include <arpa/inet.h>
#include "ide.h"
#include "duart.h"
#include "68230.h"
#include "ps2.h"

static uint8_t ram[16 << 20];	/* allocate the full 16MB of RAM */
/* 68681 */
static struct duart *duart;
/* 68230 */
static struct m68230 *pit;
/* IDE on the 230 */
static struct ide_controller *ide;

struct ps2 *ps2;

static uint8_t rcount;		/* Counter for the first 8 bytes */

static int trace = 0;

#define TRACE_MEM	0x01
#define TRACE_CPU	0x02
#define TRACE_DUART	0x04
#define TRACE_PIT	0x08
#define TRACE_RTC	0x10
#define TRACE_PS2	0x20

uint8_t fc;

/* Read/write macros */
#define READ_BYTE(BASE, ADDR) (BASE)[ADDR]
#define READ_WORD(BASE, ADDR) (((BASE)[ADDR]<<8) | \
			(BASE)[(ADDR)+1])
#define READ_LONG(BASE, ADDR) (((BASE)[ADDR]<<24) | \
			((BASE)[(ADDR)+1]<<16) | \
			((BASE)[(ADDR)+2]<<8) | \
			(BASE)[(ADDR)+3])

#define WRITE_BYTE(BASE, ADDR, VAL) (BASE)[ADDR] = (VAL)&0xff
#define WRITE_WORD(BASE, ADDR, VAL) (BASE)[ADDR] = ((VAL)>>8) & 0xff; \
			(BASE)[(ADDR)+1] = (VAL)&0xff
#define WRITE_LONG(BASE, ADDR, VAL) (BASE)[ADDR] = ((VAL)>>24) & 0xff; \
			(BASE)[(ADDR)+1] = ((VAL)>>16)&0xff; \
			(BASE)[(ADDR)+2] = ((VAL)>>8)&0xff; \
			(BASE)[(ADDR)+3] = (VAL)&0xff


unsigned int check_chario(void)
{
	fd_set i, o;
	struct timeval tv;
	unsigned int r = 0;

	FD_ZERO(&i);
	FD_SET(0, &i);
	FD_ZERO(&o);
	FD_SET(1, &o);
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	if (select(2, &i, &o, NULL, &tv) == -1) {
		perror("select");
		exit(1);
	}
	if (FD_ISSET(0, &i))
		r |= 1;
	if (FD_ISSET(1, &o))
		r |= 2;
	return r;
}

unsigned int next_char(void)
{
	char c;
	if (read(0, &c, 1) != 1) {
		printf("(tty read without ready byte)\n");
		return 0xFF;
	}
	return c;
}

/* Emulate a 68230 with a CF adapter wired data to port A control to port B
   0-2: address bits 3: /CS 4: /CS 5: W 6: R 7: reset */
void m68230_write_port(struct m68230 *pit, unsigned port, uint8_t val)
{
}

uint8_t m68230_read_port(struct m68230 *pit, unsigned port)
{
	return 0x00;
}

static struct tm *tmhold;
uint8_t rtc_status = 2;
uint8_t rtc_ce = 0;
uint8_t rtc_cf = 0;

uint8_t do_rtc_read(uint8_t addr)
{
    uint8_t r;
    if (tmhold == NULL && addr < 13)
        return 0xFF;

    switch(addr & 0x0F) {
    case 0:
        return tmhold->tm_sec % 10;
    case 1:
        return tmhold->tm_sec / 10;
    case 2:
        return tmhold->tm_min % 10;
    case 3:
        return tmhold->tm_min / 10;
    case 4:
        return tmhold->tm_hour % 10;
    case 5:
        /* Check AM/PM behaviour */
        r = tmhold->tm_hour;
        if (rtc_cf & 4)		/* 24hr */
            r /= 10;
        else if (r >= 12) {	/* 12hr PM */
            r -= 12;
            r /= 10;
            r |= 4;
        } else			/* 12hr AM */
            r /= 10;
        return r;
    case 6:
        return tmhold->tm_mday % 10;
    case 7:
        return tmhold->tm_mday / 10;
    case 8:
        return tmhold->tm_mon % 10;
    case 9:
        return tmhold->tm_mon / 10;
    case 10:
        return tmhold->tm_year % 10;
    case 11:
        return (tmhold->tm_year %100) / 10;
    case 12:
        return tmhold->tm_wday;
    case 13:
        return rtc_status;
    case 14:
        return rtc_ce;
    case 15:
        return 4;
    }
    #pragma GCC diagnostic ignored "-Wreturn-type"
}

uint8_t rtc_read(uint8_t addr)
{
    uint8_t v = do_rtc_read(addr);
    if (trace & TRACE_RTC)
        fprintf(stderr, "[RTC read %x of %X[\n", addr, v);
    return v;
}

void rtc_write(uint8_t addr, uint8_t val)
{
    if (trace & TRACE_RTC)
        fprintf(stderr, "[RTC write %X to %X]\n", addr, val);
    switch(addr) {
        case 13:
            if ((val & 0x04) == 0)
                rtc_status &= ~4;
            if (val & 0x01) {
                time_t t;
                rtc_status &= ~2;
                time(&t);
                tmhold = gmtime(&t);
            } else
                rtc_status |= 2;
            /* FIXME: sort out hold behaviour */
            break;
        case 14:
            rtc_ce = val & 0x0F;
            break;
        case 15:
            rtc_cf = val & 0x0F;
            break;
    }
}

static unsigned int irq_pending;

void recalc_interrupts(void)
{
	int i;

	// Expansion slot 1 on IRQ 1
	// IDE Interface on IRQ 2

	if (m68230_timer_irq_pending(pit))
		irq_pending |= (1 << 3);
	else
		irq_pending &= ~(1 << 3);

	if (m68230_port_irq_pending(pit))
		irq_pending |= (1 << 3);
	else
		irq_pending &= ~(1 << 3);

	if (duart_irq_pending(duart))
		irq_pending |= (1 << 4);
	else
		irq_pending &= ~(1 << 4);

	// Keyboard controller on IRQ 5
	// Expansion slot 2 on IRQ 6
	// Expansion slot 3 on IRQ 7


	/* TODO : emulate an abort button causing 7 */
	if (irq_pending) {
		for (i = 7; i >= 0; i--) {
			if (irq_pending & (1 << i)) {
				m68k_set_irq(i);
				return;
			}
		}
	} else
		m68k_set_irq(0);
}

int cpu_irq_ack(int level)
{
	if (!(irq_pending & (1 << level)))
		return M68K_INT_ACK_SPURIOUS;
	if (level == 3)
		return m68230_timer_vector(pit);
	if (level == 4)
		return duart_vector(duart);
	if (level == 3)
		return m68230_port_vector(pit);
	return M68K_INT_ACK_SPURIOUS;
}


/* Read data from RAM, ROM, or a device */
unsigned int do_cpu_read_byte(unsigned int address)
{
	address &= 0xFFFFFF;
	if (rcount < 8) {
		rcount++;
		return ram[(address) + 0xF80000];
	}
	if (address < 0x900000)
		return ram[address];
	/* ROM */
	if (address >= 0xF80000)
		return ram[address];
	if (address >= 0xF7F000 && address <= 0xF7F0FF)
		return duart_read(duart, (address & 0xFF) >> 1);
	if (address >= 0xF7F100 && address <= 0xF7F1FF)
		return m68230_read(pit, (address & 0xFF));
	if (address >= 0xF7F200 && address <= 0xF7F2FF)
		return 0x00;	// Keyboard controller
	if (address >= 0xF7F300 && address <= 0xF7F3FF)
		return ide_read8(ide, (address & 0xFF) >> 1);	// IDE Interface
	if (address >= 0xF7F400 && address <= 0xF7F4FF)
		return rtc_read((address & 0xFF) >> 1);	// RTC
	return 0xFF;
}

unsigned int cpu_read_byte(unsigned int address)
{
	unsigned int v = do_cpu_read_byte(address);
	if (trace & TRACE_MEM)
		fprintf(stderr, "RB %06X -> %02X\n", address, v);
	return v;
}

unsigned int do_cpu_read_word(unsigned int address)
{
	if (address >= 0xF7F300 && address <= 0xF7F3FF)
		return ide_read16(ide, (address & 0xFF) >> 1);

	return (do_cpu_read_byte(address) << 8) | do_cpu_read_byte(address + 1);
}

unsigned int cpu_read_word(unsigned int address)
{
	unsigned int v = do_cpu_read_word(address);
	if (trace & TRACE_MEM)
		fprintf(stderr, "RW %06X -> %04X\n", address, v);
	return v;
}

unsigned int cpu_read_word_dasm(unsigned int address)
{
	if (address < 0xFF000)
		return cpu_read_word(address);
	else
		return 0xFFFF;
}

unsigned int cpu_read_long(unsigned int address)
{
	return (cpu_read_word(address) << 16) | cpu_read_word(address + 2);
}

unsigned int cpu_read_long_dasm(unsigned int address)
{
	return (cpu_read_word_dasm(address) << 16) | cpu_read_word_dasm(address + 2);
}

void cpu_write_byte(unsigned int address, unsigned int value)
{
	address &= 0xFFFFFF;

	if (trace & TRACE_MEM)
		fprintf(stderr, "WB %06X <- %02X\n", address, value);

	if (address < 0x900000)
		ram[address] = value;
	else if (address >= 0xF7F000 && address <= 0xF7F0FF)
		duart_write(duart, (address & 0xFF) >> 1, value);
	else if (address >= 0xF7F000 && address < 0xF7F000)
		m68230_write(pit, (address & 0xFF), value);
	else if (address >= 0xF7F200 && address <= 0xF7F2FF)
		return;	// Keyboard controller
	else if (address >= 0xF7F300 && address <= 0xF7F3FF)
		ide_write8(ide, (address & 0xFF) >> 1, value);		// IDE Interface
	else if (address >= 0xF7F400 && address <= 0xF7F4FF)
		rtc_write((address & 0xFF) >> 1, value);	// RTC
}

void cpu_write_word(unsigned int address, unsigned int value)
{
	if (address >= 0xF7F300 && address <= 0xF7F3FF)
	{
		ide_write16(ide, (address & 0xFF) >> 1, value);
		return;
	}

	cpu_write_byte(address, value >> 8);
	cpu_write_byte(address + 1, value & 0xFF);
}

void cpu_write_long(unsigned int address, unsigned int value)
{
	cpu_write_word(address, value >> 16);
	cpu_write_word(address + 2, value & 0xFFFF);
}

void cpu_write_pd(unsigned int address, unsigned int value)
{
	cpu_write_word(address + 2, value & 0xFFFF);
	cpu_write_word(address, value >> 16);
}

void cpu_instr_callback(void)
{
	if (trace & TRACE_CPU) {
		char buf[128];
		unsigned int pc = m68k_get_reg(NULL, M68K_REG_PC);
		m68k_disassemble(buf, pc, M68K_CPU_TYPE_68000);
		fprintf(stderr, ">%06X %s\n", pc, buf);
	}
}

static void device_init(void)
{
	irq_pending = 0;
	ide_reset_begin(ide);
	duart_reset(duart);
	duart_set_input(duart, 1);
	m68230_reset(pit);
}

static struct termios saved_term, term;

static void cleanup(int sig)
{
	tcsetattr(0, 0, &saved_term);
	exit(1);
}

static void exit_cleanup(void)
{
	tcsetattr(0, 0, &saved_term);
}


static void take_a_nap(void)
{
	struct timespec t;
	t.tv_sec = 0;
	t.tv_nsec = 100000;
	if (nanosleep(&t, NULL))
		perror("nanosleep");
}

void cpu_pulse_reset(void)
{
	device_init();
}

void cpu_set_fc(int fc)
{
}

void usage(void)
{
	fprintf(stderr, "ddraig68k [-r rompath] [-f] [-d debug].\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int fd;
	int cputype = M68K_CPU_TYPE_68000;
	int fast = 0;
	int opt;
	const char *romname = NULL;
	const char *diskname = NULL;

	//trace |= TRACE_DUART;

	while((opt = getopt(argc, argv, "i:r:d:f")) != -1) {
		switch(opt) {
		case 'd':
			trace = atoi(optarg);
			break;
		case 'f':
			fast = 1;
			break;
		case 'i':
			diskname = optarg;
			break;
		case 'r':
			romname = optarg;
			break;
		default:
			usage();
		}
	}

	if (tcgetattr(0, &term) == 0) {
		saved_term = term;
		atexit(exit_cleanup);
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, cleanup);
		signal(SIGTSTP, SIG_IGN);
		term.c_lflag &= ~ICANON;
		term.c_iflag &= ~(ICRNL | IGNCR);
		term.c_cc[VMIN] = 1;
		term.c_cc[VTIME] = 0;
		term.c_cc[VINTR] = 0;
		term.c_cc[VSUSP] = 0;
		term.c_cc[VEOF] = 0;
		term.c_lflag &= ~(ECHO | ECHOE | ECHOK);
		tcsetattr(0, 0, &term);
	}

	if (optind < argc)
		usage();

	memset(ram, 0xA7, sizeof(ram));

	fd = open(romname, O_RDONLY);
	if (fd == -1) {
		perror(romname);
		exit(1);
	}
	/* copying the image is fine as this is read only space */
	if (read(fd, ram + 0xF80000, 0x8000) < 0x1000) {
		fprintf(stderr, "%s: too small.\n", romname);
		exit(1);
	}
	close(fd);

	if (diskname) {
		fd = open(diskname, O_RDWR);
		if (fd == -1) {
			perror(diskname);
			exit(1);
		}
	}
	ide = ide_allocate("hd0");
	if (ide == NULL)
		exit(1);
	if (diskname && ide_attach(ide, 0, fd))
		exit(1);

	duart = duart_create();
	if (trace & TRACE_DUART)
		duart_trace(duart, 1);

	pit = m68230_create();
	if (trace & TRACE_PIT)
		m68230_trace(pit, 1);

	m68k_init();
	m68k_set_cpu_type(cputype);
	m68k_pulse_reset();

	/* Init devices */
	device_init();


	while (1) {
		m68k_execute(1000);
		duart_tick(duart);
		m68230_tick(pit, 1000);
		if (!fast)
			take_a_nap();
	}
}
