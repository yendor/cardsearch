#!/usr/bin/env python

import getopt, sys, os, re, time

class CardSearch:
    def __init__(self):
         self.output_filename = "/var/log/cardsearch.log"
         self.start_path = "/"

         self.lines_per_scan = 50
         self.sleep_per_scan = 1

         shortargs = 'o:f:d:'
         longargs = ['output=', 'config=', 'start=']

         options, remainder = getopt.getopt(sys.argv[1:], shortargs, longargs)

         for opt, arg in options:
             if opt in ('-o', '--output'):
                 self.output_filename = os.path.abspath(arg)
             elif opt in ('-f', '--config'):
                 self.config_filename = arg
             elif opt in ('-d', '--start'):
                 self.start_path = os.path.abspath(arg)

         self.whitelist_filenames = [self.output_filename, "/proc", "/dev"]
         print >> sys.stderr, "Sleeping for %d microseconds every %d lines per file scanned" % (self.sleep_per_scan, self.lines_per_scan)

    def search(self):
        if os.path.isdir(self.start_path):
            try:
                self.output_file = open(self.output_filename, 'w')
            except IOError:
                print >> sys.stderr, "Can't open log file %s for writing" % (self.output_filename)
                sys.exit(1)

            self.walk(self.start_path)
        else:
            print "Starting directory %s does not exist, exiting." % (self.start_path)
            sys.exit(1)

    def walk(self, dir):
        try:
            for name in os.listdir(dir):
                path = os.path.join(dir,name)

                if path in self.whitelist_filenames:
                    print >> sys.stderr, "Skipping %s due to whitelisting" % (path)
                    continue

                if os.path.isfile(path):
                    self.check(path)
                elif os.path.isdir(path) and not os.path.islink(path):
                    self.walk(path)
        except OSError:
            print >> sys.stderr, "Permission denied to %s" % (dir)

    def check(self, filepath):
        try:
            f = open(filepath, 'r')

            confirmed_matches = []

            linenum=0

            for line in f:
                linenum = linenum + 1
                cardpattern = re.compile('\d{12,19}')

                matches = cardpattern.findall(line)

                if matches:
                    for match in matches:
                        if (possible_credit_card(match)):
                            confirmed_matches.append(match)
                if linenum % self.lines_per_scan == 0:
                    usleep(self.sleep_per_scan)
            if confirmed_matches:
                self.output_file.write("Found %d matches in %s\n" % (len(confirmed_matches), filepath))
                for match in confirmed_matches:
                    self.output_file.write("%s\n" % (match))

        except IOError:
            print >> sys.stderr, "Can't read %s" % (filepath)

def possible_credit_card(cardnum):
    if cardnum == "0" * len(cardnum):
        return False

    return is_luhn_valid(cardnum)

def is_luhn_valid(cc):
     num = map(int, cc)
     return not sum(num[::-2] + map(lambda d: sum(divmod(d * 2, 10)), num[-2::-2])) % 10

def usleep(micro_seconds):
    time.sleep(micro_seconds / 1000000.0)

if __name__ == "__main__":
    s = CardSearch()
    s.search()