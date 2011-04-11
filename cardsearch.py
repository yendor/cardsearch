#!/usr/bin/env python

import getopt, sys, os, re, time
import syslog

import traceback

class CardSearch:
    def __init__(self):
        self.output_filename = ""
        self.start_paths = None

        self.lines_per_scan = 0
        self.sleep_per_scan = 0
        self.syslog = False
        self.verbose = True
        self.output_file = False
        self.whitelist_extensions = set();
        self.chunksize = 1024*1024
        self.cardpattern = re.compile(r'(?<!pub-)\b\d{12,19}\b')
        shortargs = 'o:sqe:c:'
        longargs = ['output=', 'syslog', 'quiet', 'noextensions=', 'chunksize=']

        options, self.start_paths = getopt.getopt(sys.argv[1:], shortargs, longargs)

        for opt, arg in options:
            if opt in ('-o', '--output'):
                self.output_filename = os.path.abspath(arg)
            elif opt in ('-q', '--quiet'):
                self.verbose = False
            elif opt in ('-s', '--syslog'):
                self.syslog = True
            elif opt in ('-e', '--noextensions'):
                self.whitelist_extensions = set(arg.split(','))
            elif opt in ('-c', '--chunksize'):
                self.chunksize = arg

        if self.start_paths == None:
            print >> sys.stderr, "You must specify the path(s) to scan"
            sys.exit(1)

        self.whitelist_filenames = set([self.output_filename, "/proc", "/dev", "/sys"])

    def search(self):
        self.loginit()
        for path in set(self.start_paths):
            full_path = os.path.abspath(path)
            if os.path.exists(full_path):
                self.walk(full_path)
            else:
                print >> sys.stderr, "WARNING: The path %s does not exist" % (full_path)

    def walk(self, start):
        try:
            if os.path.isfile(start):
                (basename, ext) = os.path.splitext(start)
                ext = ext.replace('.', '', 1)
                if ext not in self.whitelist_extensions:
                    self.check(start)
            elif os.path.isdir(start) and not os.path.islink(start):
                for name in os.listdir(start):
                    path = os.path.join(start,name)
                    if path not in self.whitelist_filenames:
                        self.walk(path)

        except OSError:
            traceback.print_exc(file=sys.stdout)
            if self.verbose == True:
                print >> sys.stderr, "Permission denied to %s" % (dir)

    def check(self, filepath):
        try:
            last_pos = 0;

            f= open(filepath, 'r')

            confirmed_matches = []

            linenum=0
            chunk = f.read(self.chunksize)

            while not f.closed:
                linenum = linenum + 1

                matches = self.cardpattern.finditer(chunk)

                if matches:
                    for match in matches:
                        matchedString = match.group(0)

                        if (possible_credit_card(matchedString)):
                            if self.verbose:
                                context = getContext(chunk, match)
                                print "%s - %s\n%s\n" % (filepath, matchedString, context)
                            else:
                                confirmed_matches.append(matchedString)
                f.seek(-19, os.SEEK_CUR)
                chunk = f.read(self.chunksize)
                # If we can't read any more from the file, close it
                if last_pos == f.tell():
                    f.close()
                else:
                    last_pos = f.tell()

            if confirmed_matches and not self.verbose:
                self.log("Found %d matches in %s\n" % (len(confirmed_matches), filepath))

        except IOError:
            if not self.verbose:
                print >> sys.stderr, "Can't read %s" % (filepath)

    def loginit(self):
        try:
            if self.output_filename and self.syslog == False:
                self.output_file = open(self.output_filename, 'w')
            elif self.syslog == True:
                syslog.openlog('cardsearch')

        except IOError:
            print >> sys.stderr, "Can't open log file %s for writing" % (self.output_filename)
            sys.exit(1)

    def log(self, message):
        if self.syslog:
            syslog.syslog(message)
        if self.output_file:
             self.output_file.write(message)

def possible_credit_card(cardnum):
    if is_test_cardnum(cardnum):
        return False

    cardlen = len(cardnum)

    if cardnum == "0" * cardlen:
        return False

    # American Express
    if int(cardnum[:2]) in [34, 37] and cardlen == 15:
        return is_luhn_valid(cardnum)

    # Bankcard
    if int(cardnum[:4]) in [5610] and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Bankcard
    if int(cardnum[:6]) in range(560221, 560225) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Diners Club Carte Blanche
    if int(cardnum[:3]) in range(300, 305) and cardlen == 14:
        return is_luhn_valid(cardnum)

    # Diners Club International
    if int(cardnum[:2]) in [36] and cardlen == 14:
        return is_luhn_valid(cardnum)

    # Diners Club United States and Canada
    if int(cardnum[:2]) in range(54, 55) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Discover Card
    if int(cardnum[:4]) in [6011] and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Discover Card
    if int(cardnum[:6]) in range(622126, 622925) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Discover Card
    if int(cardnum[:3]) in range(644, 649) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Discover Card
    if int(cardnum[:2]) in [65] and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Instapaymment
    if int(cardnum[:3]) in range(637, 639) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # JCB
    if int(cardnum[:4]) in range(3528, 3589) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Maestro
    if int(cardnum[:4]) in [5018, 5020, 5020, 5038, 6304, 6759, 6761, 6763] and cardlen in range(12, 19):
        return is_luhn_valid(cardnum)

    # MasterCard
    if int(cardnum[:2]) in range(51, 55) and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Solo
    if int(cardnum[:4]) in [6334, 6767] and cardlen in [6, 18, 19]:
        return is_luhn_valid(cardnum)

    # Switch
    if int(cardnum[:4]) in [4903, 4905, 4911, 4936, 6333, 6759] and cardlen in [16, 18, 19]:
        return is_luhn_valid(cardnum)

    # Switch
    if int(cardnum[:6]) in [564182, 633110] and cardlen in [16, 18, 19]:
        return is_luhn_valid(cardnum)

    # Visa
    if int(cardnum[:1]) in [4] and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Visa Elecrton
    if int(cardnum[:4]) in [4026, 4508, 4844, 4913, 4917] and cardlen == 16:
        return is_luhn_valid(cardnum)

    # Visa Electron
    if int(cardnum[:6]) in [417500] and cardlen == 16:
        return is_luhn_valid(cardnum)

    return False

def is_test_cardnum(cc):
    testNums = set()
    testNums.add("4111111111111111")
    testNums.add("4005550000000001")
    testNums.add("4200000000000000")
    testNums.add("5123456789012346")
    testNums.add("5313581000123430")
    testNums.add("4557012345678902")
    testNums.add("345678901234564")
    testNums.add("5610901234567899")
    testNums.add("30123456789019")
    testNums.add("4222222222222")
    testNums.add("370000000000002")
    testNums.add("5424000000000015")
    testNums.add("6011000000000012")
    testNums.add("4007000000027")
    return cc in testNums

def is_luhn_valid(cc):
     num = map(int, cc)
     return not sum(num[::-2] + map(lambda d: sum(divmod(d * 2, 10)), num[-2::-2])) % 10

def usleep(micro_seconds):
    time.sleep(micro_seconds / 1000000.0)

def getContext(line, m, contextAmount=40):
    bold = "\033[1m"
    reset = "\033[0;0m"
    line = line.strip()

    context = line[m.start()-contextAmount:m.start()] + bold + line[m.start():m.end()] + reset + line[m.end():m.end()+contextAmount]
    return context

if __name__ == "__main__":
    s = CardSearch()
    s.search()