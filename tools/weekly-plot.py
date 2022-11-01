import datetime as dt
import  os


class Sample(object):
    def __init__(self):
        self.tests_vs_first = dict()
        self.tests_vs_last = dict()

    def add_info(self, size, test_name, vs_first, vs_last):
        try:
            if size != self.size:
                raise ValueError("size != self.size", size, self.size)
        except AttributeError:
            self.size = size

        if test_name == "-":
            return

        if test_name in self.tests_vs_first or test_name in self.tests_vs_last:
                raise ValueError("Overrwriting test!", size, test_name, vs_first, vs_last, self.tests_vs_first[test_name], self.tests_vs_last[test_name])

        self.tests_vs_first[test_name] = vs_first
        self.tests_vs_last[test_name] = vs_last

    def __str__(self):
        res = "size: {}\n".format(self.size)
        for k, v in self.tests_vs_first.items():
            res += "  " + k + " vs first: " + v + "\n"
        for k, v in self.tests_vs_last.items():
            res += "  " + k + " vs last: " + v + "\n"
        return res

samples = dict() # (name) -> Sample

def add_sample(name, ts, size, test, vs_first, vs_last):
    if name not in samples:
        samples[name] = dict()
    if ts not in samples[name]:
        samples[name][ts] = Sample()
    #samples[name][ts].add_info(size, test, vs_first, vs_last)
    samples[name][ts].add_info(size, test, inverse_float(vs_first), inverse_float(vs_last))


def inverse_float(x):
    # (str) -> str
    if x == "" or x == "-":
        return x
    if x.startswith("."):
        x = "0" + x
    return str(1.0 - float(x))

def print_gnu_data(label, sorted_times, y):
    if len(sorted_times) != len(y):
        print "len(sorted_times) %s != len(y) %s" % (len(sorted_times), len(y))
        return
    total_len = len(sorted_times)
    ii = 0
    with open("churn_" + label.replace(" ", "_") + ".dat", "w") as f:
        f.write("time,count\n")
        while ii < total_len:
            f.write("%s,%s\n" % (sorted_times[ii], y[ii]))
            ii += 1


with open("weekly-12-12-18.log") as f:
    lines = f.readlines()
    lines = [x.strip() for x in lines]

i = 0
while i < len(lines):
    line=lines[i]
    if line.startswith("From"):
        epoch_ts_start = line.split(" ")[1]
        epoch_ts_end = line.split(" ")[5]
        i+=4
        continue
    columns = line.split("|")
    columns = [x.strip() for x in columns]
    if len(columns) == 1:
        i += 1
        continue
    if columns[1] != "":
        name = columns[1]
    if columns[2] != "":
        size = columns[2]
    test = columns[3]
    vs_first_week = columns[4]
    vs_last_week = columns[5]
    add_sample(name, epoch_ts_start, size, test, vs_first_week, vs_last_week)
    i += 1

import matplotlib.pyplot as plt
import matplotlib.dates as md





#tests = ["Overlap", "Jaccard"]
tests = ["wl conn", "wl fp"]
for test in tests:
    for sample_name, sample in samples.items():

        if sample_name != "seen > 10000":
            continue
        plt.subplots_adjust(bottom=0.2)
        plt.xticks(rotation=25)
        ax = plt.gca()
        plt.tick_params(axis='both', which='major', labelsize=24)
        xfmt = md.DateFormatter('%Y-%m-%d')
        import matplotlib.ticker as plticker
        ax.xaxis.set_major_formatter(xfmt)
        loc = plticker.MultipleLocator(base=30.2)  # this locator puts ticks at regular intervals
        ax.xaxis.set_major_locator(loc)

        plt.gcf().autofmt_xdate()
        plot_sample_sizes = False
        if sample_name.startswith("top") and test == "Overlap":
            plot_sample_sizes = True
            plt.ylim(0, 1.1 * int(sample_name[3:]))
        if test == "Jaccard" or test.startswith("wl "):
            plt.ylim(0, 1.0)

        def get_sorted_times(skip_after_zero):
            time_sorted = []
            skip_once = True
            for time in sorted(sample.iterkeys()):
                if sample[time].size == "0":
                    if skip_after_zero:
                        skip_once = True
                    continue
                if skip_once:
                    skip_once = False
                    continue
                time_sorted.append(time)
            return time_sorted

        def get_datenums(skip_after_zero):
            dates = [dt.datetime.fromtimestamp(float(ts)) for ts in get_sorted_times(skip_after_zero)]
            return md.date2num(dates)

        # ax.set_title(test + " " + sample_name)

        if plot_sample_sizes:
            y = []
            for time in get_sorted_times(False):
                y.append(sample[time].size)
            plt.plot(get_datenums(False), y, "p-", label='sample size')

        y = []
        for time in get_sorted_times(False):
            if test not in sample[time].tests_vs_first:
                continue
            y.append(sample[time].tests_vs_first[test])
        if len(y) != 0:
            #plt.plot(get_datenums(False), y, "p-", label='vs first week')
            if test == "wl fp":
                label = "blocked fingerprints"
            if test == "wl conn":
                label = "blocked connections"
            print_gnu_data(label, get_sorted_times(False), y)
            plt.plot(get_datenums(False), y, "p-", label=label)
        y = []
        for time in get_sorted_times(True):
            if test not in sample[time].tests_vs_last or \
                sample[time].tests_vs_last[test] == "-":
                continue
            y.append(sample[time].tests_vs_last[test])
        if len(y) != 0:
            plt.plot(get_datenums(True), y, "p-", label='vs last week')

        leg = plt.legend(loc='upper center', fontsize=26, ncol=2, mode="expand", shadow=True, fancybox=True)
        if leg is None:
            print "skipping", test, sample_name
            continue
        leg.get_frame().set_alpha(0.4)

#plt.savefig("path")
plt.show()
plt.cla()
