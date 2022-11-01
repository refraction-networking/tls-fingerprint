(function () {

var divid = {{ divid|tojson|safe }};
var uniqueid = divid.replace('#', '');
var canvas_div = document.querySelector(divid),
    canvas = canvas_div.querySelector('canvas'),
	context = canvas.getContext("2d");



var ylabel = canvas.getAttribute('ylabel'),
    yformat = canvas.getAttribute('yformat'),
    yrange = canvas.getAttribute('yrange'),
    grid = canvas.getAttribute('grid');


// Defaults
if (ylabel  === null) { ylabel  = ""; }
if (grid    === null) { grid    = true; }


var margin = {top: 20, right: 20, bottom: 40, left: 80},
    width = canvas.width - margin.left - margin.right,
    height = canvas.height - margin.top - margin.bottom;

var parseTime = d3.timeParse("%s");

var x = d3.scaleTime()
    .range([0, width]);

var y = d3.scaleLinear()
    .range([height, 0]);

var line = d3.line()
    .x(function(d) { return x(d.time); })
    .y(function(d) { return y(d.count); })
    .curve(d3.curveLinear)  //curveStep, curveLinear, curveNatural?
    .context(context);

context.translate(margin.left, margin.top);

d3.csv({{ path|tojson|safe }}, function(d) {
  d.time = parseTime(d.time);
  d.count = +d.count;
  return d;
}).then(function(data) {
  x.domain(d3.extent(data, function(d) { return d.time; }));
  y.domain(d3.extent(data, function(d) { return d.count; }));


  if (yrange != null) {
      d = yrange.split(',');
      y = y.domain([d[0], d[1]]);
  }

  xAxis();
  yAxis();

  context.beginPath();
  line(data);
  context.lineWidth = 3.5;
  context.strokeStyle = "steelblue";
  context.stroke();
});

function xAxis() {
  var tickCount = 10,
      tickSize = 6,
      ticks = x.ticks(tickCount),
      tickFormat = x.tickFormat();

  context.beginPath();
  ticks.forEach(function(d) {
    context.moveTo(x(d), height + tickSize);
    if (grid) {
        context.lineTo(x(d), 0);
    } else {
        context.lineTo(x(d), height);
    }
  });
  context.strokeStyle = "#ddd";
  context.stroke();

  context.beginPath();
  context.moveTo(0, height+tickSize);
  context.lineTo(0, height);
  context.lineTo(width, height);
  context.lineTo(width, height+tickSize);
  context.strokeStyle = "black";
  context.stroke();

  context.font = "10pt Sans Serif";
  context.textAlign = "center";
  context.textBaseline = "top";
  ticks.forEach(function(d) {
    context.fillText(tickFormat(d), x(d), height + tickSize);
  });
}

function yAxis() {
  var tickCount = 10,
      tickSize = 6,
      tickPadding = 3,
      ticks = y.ticks(tickCount),
      tickFormat = y.tickFormat();

  if (yformat != null) {
    tickFormat = d3.format(yformat);
  }

  context.beginPath();
  ticks.forEach(function(d) {
    context.moveTo(-tickSize, y(d));
    if (grid) {
        context.lineTo(width, y(d));
    } else {
        context.lineTo(0, y(d));
    }
  });
  context.strokeStyle = "#ddd";
  context.stroke();

  context.beginPath();
  context.moveTo(-tickSize, 0);
  context.lineTo(0, 0);
  context.lineTo(0, height);
  context.lineTo(-tickSize, height);
  context.strokeStyle = "black";
  context.stroke();

  context.font = "10pt Sans Serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  ticks.forEach(function(d) {
    //console.log('tick('+d+')='+tickFormat(d));
    context.fillText(tickFormat(d), -tickSize - tickPadding, y(d));
  });

  context.save();
  context.rotate(-Math.PI / 2);
  context.textAlign = "right";
  context.textBaseline = "top";
  context.font = "bold 10pt sans-serif";
  context.fillText(ylabel, -10, 10);
  context.restore();
}



/*
    var canvas = d3.select(divid);
    var context = canvas.getContext("2d");
    var margin = {
        top: 20,
        right: 80,
        bottom: 30,
        left: 50
      },
      width = 900 - margin.left - margin.right,
      height = 500 - margin.top - margin.bottom;

    //var parseDate = d3.time.format("%s").parse;
    var parseDate = d3.timeParse("%s");

    var x = d3.scaleTime()
      .range([0, width]);

    var y = d3.scaleLinear()
      .range([height, 0]);

    //var color = d3.scale.category10();

    var xAxis = d3.svg.axis()
      .scale(x)
      .orient("bottom");

    var yAxis = d3.svg.axis()
      .scale(y)
      .orient("left");

    var line = d3.line()
      .x(function(d) { return x(d.time); })
      .y(function(d) { return y(d.count);});

    var svg = d3.select(divid).append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
      .append("g")
      .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var data = d3.csv(
                    {{ path|tojson|safe }}, function(data) {
      data.forEach(function(d) {
        //d.time = new Date(parseInt(d.time)*1000);
        d.time = parseInt(d.time);
	    d.count = parseFloat(d.count);
        //console.log(d);
      });

      color.domain(d3.keys(data[0]).filter(function(key) {
        return key !== "time";
      }));

        // Fill zeros in data
        var fill_zeros = {{ fill_zeros|tojson|safe }};
        if (fill_zeros) {
            var i = 0;
            while (i < data.length - 1) {
                var expected_t = data[i].time + 3600;
                if (data[i+1].time != expected_t) {
                    var next_t = data[i+1].time - 3600;
                    data.splice(i+1, 0, {time: expected_t, count: 0});
                    if (expected_t != next_t) {
                        data.splice(i+2, 0, {time: next_t, count: 0});
                        i++;
                    }
                    i++
                }
                //console.log(i + " out of " + data.length + ": " + data[i].time + ", " + data[i].count);
                i++;
            }
        }
        data.forEach(function(d) {
            d.time = new Date(parseInt(d.time)*1000);
            //console.log(d);
        });

      var dlines = color.domain().map(function(name) {
        return {
          name: name,
          values: data.map(function(d) {
            return {
              time: d.time,
              count: +d[name]
            };
          })
        };
      });

      x.domain(d3.extent(data, function(d) {
        return d.time;
      }));

      y.domain([
        d3.min(dlines, function(c) {
          return d3.min(c.values, function(v) {
            return v.count;
          });
        }),
        d3.max(dlines, function(c) {
          return d3.max(c.values, function(v) {
            return v.count;
          });
        })
      ]);

      var legend = svg.selectAll('g')
        .data(dlines)
        .enter()
        .append('g')
        .attr('class', 'legend');

      legend.append('rect')
        .attr('x', width - 20)
        .attr('y', function(d, i) {
          return i * 20;
        })
        .attr('width', 10)
        .attr('height', 10)
        .style('fill', function(d) {
          return color(d.name);
        });

      legend.append('text')
        .attr('x', width - 8)
        .attr('y', function(d, i) {
          return (i * 20) + 9;
        })
        .text(function(d) {
          return d.name;
        });

      svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis);

      svg.append("g")
        .attr("class", "y axis")
        .call(yAxis)
        .append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 6)
        .attr("dy", ".71em")
        .style("text-anchor", "end")
        .text("");

      var dline = svg.selectAll(".city")
        .data(dlines)
        .enter().append("g")
        .attr("class", "city");

      dline.append("path")
        .attr("class", "line line-"+uniqueid)
        .attr("d", function(d) {
          return line(d.values);
        })
        .style("stroke", function(d) {
          return color(d.name);
        });

      dline.append("text")
        .datum(function(d) {
          return {
            name: d.name,
            value: d.values[d.values.length - 1]
          };
        })
        .attr("transform", function(d) {
          return "translate(" + x(d.value.time) + "," + y(d.value.count) + ")";
        })
        .attr("x", 3)
        .attr("dy", ".35em")
        .text(function(d) {
          return d.name;
        });

      var mouseG = svg.append("g")
        .attr("class", "mouse-over-effects-"+uniqueid);

      mouseG.append("path") // this is the black vertical line to follow mouse
        .attr("class", "mouse-line-"+uniqueid)
        .style("stroke", "black")
        .style("stroke-width", "1px")
        .style("opacity", "0");

      var lines = document.getElementsByClassName('line-'+uniqueid);

      var mousePerLine = mouseG.selectAll('.mouse-per-line-'+uniqueid)
        .data(dlines)
        .enter()
        .append("g")
        .attr("class", "mouse-per-line-"+uniqueid);

      mousePerLine.append("circle")
        .attr("r", 7)
        .style("stroke", function(d) {
          return color(d.name);
        })
        .style("fill", "none")
        .style("stroke-width", "1px")
        .style("opacity", "0")
        .attr("id", "mouse-line-circle-"+uniqueid);

      mousePerLine.append("text")
        .attr("transform", "translate(10,3)")
        .attr("id", "mouse-line-text-"+uniqueid);

      mouseG.append('svg:rect') // append a rect to catch mouse movements on canvas
        .attr('width', width) // can't catch mouse events on a g element
        .attr('height', height)
        .attr('fill', 'none')
        .attr('pointer-events', 'all')
        .on('mouseout', function() { // on mouse out hide line, circles and text
          d3.select(".mouse-line-"+uniqueid)
            .style("opacity", "0");
          d3.selectAll(".mouse-per-line-"+uniqueid +" circle")
            .style("opacity", "0");
          d3.selectAll(".mouse-per-line-"+uniqueid +" text")
            .style("opacity", "0");
        })
        .on('mouseover', function() { // on mouse in show line, circles and text
          d3.select(".mouse-line-"+uniqueid)
            .style("opacity", "1");
          d3.selectAll(".mouse-per-line-"+uniqueid +" circle")
            .style("opacity", "1");
          d3.selectAll(".mouse-per-line-"+uniqueid+" text")
            .style("opacity", "1");
        })
        .on('mousemove', function() { // mouse moving over canvas
                        var mouse = d3.mouse(this);
                        d3.select(".mouse-line-"+uniqueid)
                        .attr("d", function() {
                                        var d = "M" + mouse[0] + "," + height;
                                        d += " " + mouse[0] + "," + 0;
                                        return d;
                                        });

                        d3.select(".mouse-per-line-"+uniqueid)
                        .attr("transform", function(d, i) {
                                        //console.log(width/mouse[0])
                                        var xDate = x.invert(mouse[0]),
                                        bisect = d3.bisector(function(d) { return d.time; }).right;
                                        idx = bisect(d.values, xDate);
                                        var beginning = 0,
                                        end = lines[i].getTotalLength(),
                                        target = null;

                                        while (true){
                                        target = Math.floor((beginning + end) / 2);
                                        pos = lines[i].getPointAtLength(target);
                                        if ((target === end || target === beginning) && pos.x !== mouse[0]) {
                                        break;
                                        }
                                        if (pos.x > mouse[0])      end = target;
                                        else if (pos.x < mouse[0]) beginning = target;
                                        else break; //position found
                                        }
                                        d3.select('#mouse-line-text-'+uniqueid)
                                        .text(y.invert(pos.y).toFixed(2));
                                        return "translate(" + mouse[0] + "," + pos.y +")";
                        });
            });
        });
*/
})();
