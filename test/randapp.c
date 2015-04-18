/*
 * Generate a random app
 *
 * Copyright (C) 2004-2005 Benjamin Moody
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 * USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include <time.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#else
# define getpid() 0
#endif

#if PROTOTYPES
# define proto(x) x
#else
# define proto(x) ()
#endif

#if !HAVE_RANDOM
# if HAVE_RAND
#  undef random
#  undef srandom
#  define random rand
#  define srandom srand
# endif
#endif

struct hexinfo {
  int last_r, last_w, last_a;
  int rec_addr, rec_pos;
  unsigned char currec[256];
};

void write_file_hex_byte proto((FILE* f, struct hexinfo *inf, int rectype,
				int width, int addr, int x));
void write_file_hex proto((FILE* f, const unsigned char *data, size_t length));

static const unsigned char appstart[]={0x80,0x0f, 0x00,0x00,0x00,0x00,
				       0x80,0x12, 0x42, 0x04,
				       0x80,0x21, 0x01,
				       0x80,0x31, 0x01,
				       0x80,0x48, 'T','e','s','t',' ','A','p','p',
				       0x80,0x81, 0x01,
				       0x03,0x26,
				       0x09,0x04, 0x00,0x00,0x00,0x00,
				       0x02,0x0d, 0x04,0xde,0xad,0xbe,0xef,
				       0x80,0x7F, 0x00,0x00,0x00,0x00};

int main(argc, argv)
     int argc;
     char** argv;
{
  unsigned char data[2000];
  size_t size, i;
  unsigned int z;

  srandom(time(NULL) + (100 * getpid()));

  size = sizeof(appstart) + (random() % 1000);

  for (i=0; i<sizeof(appstart); i++)
    data[i] = appstart[i];

  data[5] = (size-6);
  data[4] = (size-6)>>8;
  data[3] = (size-6)>>16;
  data[2] = (size-6)>>24;

  if (argc > 1) {
    sscanf(argv[1], "%X", &z);
    data[8] = (z>>8)&0xff;
    data[9] = z&0xff;
  }

  for (; i<size; i++)
    data[i] = random() & 0xff;

  data[i++] = 0x02;
  data[i++] = 0x2d;
  data[i++] = 0x40;

  for (; i<size+67; i++)
    data[i] = random() & 0xff;

  data[i++] = 1;
  data[i++] = random() % 4;

  write_file_hex(stdout, data, i);

  return 0;
}

void write_file_hex_byte(f, inf, rectype, width, addr, x)
     FILE* f;
     struct hexinfo *inf;
     int rectype;
     int width;
     int addr;
     int x;
{
  int c, i;

  if (rectype != inf->last_r || width != inf->last_w ||
      addr != (inf->last_a+1) || inf->rec_pos >= inf->last_w) {

    /* then we must flush the last record */
    if (inf->last_r != -1 && (inf->last_w==0 || inf->rec_pos!=0)) {
      fprintf(f,":%02X%02X%02X%02X",inf->rec_pos,(inf->rec_addr>>8)&0xff,
	      inf->rec_addr&0xff,inf->last_r);
      c = inf->rec_pos + inf->last_r + inf->rec_addr + (inf->rec_addr>>8);
      
      for (i=0;i<(inf->rec_pos);i++) {
	fprintf(f,"%02X",(int)inf->currec[i]);
	c += inf->currec[i];
      }
      
      fprintf(f,"%02X\r\n",(-c)&0xff);
    }

    /* we're starting a new record now */
    inf->last_r = rectype;
    inf->last_w = width;
    inf->rec_addr = addr;
    inf->rec_pos = 0;
  }

  if (width) {
    inf->currec[inf->rec_pos]=x;
    inf->rec_pos++;
  }

  inf->last_a = addr;
}


/* Write an output file */

void write_file_hex(f, data, length)
     FILE* f;
     const unsigned char *data;
     size_t length;
{
  int pagenum=0;
  size_t i;
  struct hexinfo inf;

  inf.last_r = inf.last_w = inf.last_a = -1;
  inf.rec_addr = -1;
  inf.rec_pos = 0;

  for (i=0;i<length;i++) {

    if (((int)i&0x3fff)==0) {
      write_file_hex_byte(f,&inf,2,2,0,0);
      write_file_hex_byte(f,&inf,2,2,1,pagenum);
      pagenum++;
    }

    write_file_hex_byte(f,&inf,0,32,((int)i&0x3fff)|0x4000,data[i]);
  }

  write_file_hex_byte(f,&inf,1,0,0,0);	/* end record */
  write_file_hex_byte(f,&inf,-1,0,0,0);	/* flush output */
}
