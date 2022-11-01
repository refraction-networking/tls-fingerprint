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

set style line 1 lt rgb "#654EA3" lw 1 pt 1
set style line 2 lt rgb "#FFD662" lw 1 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9

set output './churn.pdf'

set yrange [0:1]

set xdata time
set timefmt "%s"
set format x "%b '%y"
set xtics rotate by -45 offset -0.8,0
#("1514790000", "1517468400", "1519887600", "1522562400", "1525154400", "1527832800", "1530424800", "1533103200", "1535781600", "1538373600", "1541052000", )
#set xrange ["1512900400":"1534713600"]
set xrange ["1512900400":"1544400000"]

#set format y '%.f'
set xlabel 'Time'
set ylabel 'Fraction blocked'

set datafile separator ","

plot 'churn_blocked_connections.dat' u 1:2 w lines title 'Blocked connections' ls 1, \
    'churn_blocked_fingerprints.dat' u 1:2 w lines title 'Blocked fingerprints' ls 2

