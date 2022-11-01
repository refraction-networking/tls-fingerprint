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
set style line 1 lt rgb "#B00000" lw 0.5 pt 1
set style line 2 lt rgb "#00B000" lw 1 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9

set output './group-size.pdf'

set xlabel 'Fingerprint cluster'

set ylabel 'Cumulative fraction of fingerprints'


plot 'group-sizes.dat' u 1:2 w lines notitle ls 1

