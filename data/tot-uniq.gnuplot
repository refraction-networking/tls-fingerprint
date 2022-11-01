# style from http://youinfinitesnake.blogspot.com/2011/02/attractive-scientific-plots-with.html

set terminal pdfcairo font "Gill Sans,12" linewidth 4 rounded

set style line 80 lt rgb "#808080"

set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
             # borders are useless and make it harder
             # to see plotted lines near the border.
    # Also, put it in grey; no need for so much emphasis on a border.
set xtics nomirror
set ytics nomirror

#set style line 1 lc rgb '#8b1a0e' pt 1 ps 1 lt 1 lw 2 # --- red
#set style line 2 lc rgb '#5e9c36' pt 6 ps 1 lt 1 lw 2 # --- green
set style line 1 lt rgb "#B00000" lw 1 pt 1
set style line 2 lt rgb "#00B000" lw 1 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9

set output './tot-uniq.pdf'

set xdata time
set timefmt "%s"
set format x "%b %d, %Y"
set xtics rotate by -45 offset -0.8,0
#set xrange ["Oct 28, 2017":"May 2, 2018"]
#date --date="Oct 27, 2017" +"%s"
#set xrange ["1509084000":"1525240800"]
set xrange ["1509084000":"1533081600"]   # till aug 1st


#set format y '%.f'
set xlabel 'Time'
set ylabel 'Total Unique Fingerprints'

set datafile separator ","

plot 'tot-uniq' u 1:2 w lines notitle ls 1



set output './tot-uniq-1k.pdf'
plot 'cumulative-unique-1k' u 1:2 w lines notitle ls 1

set output './tot-uniq-10k.pdf'
plot 'cumulative-unique-10k' u 1:2 w lines notitle ls 1

