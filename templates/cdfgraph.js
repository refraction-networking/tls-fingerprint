(function () {

    var divid = {{ divid|tojson|safe }};
    var uniqueid = divid.replace('#', '');
    var canvas_div = document.querySelector(divid),
        canvas = canvas_div.querySelector('canvas'),
        context = canvas.getContext('2d');

    var ylabel = canvas.getAttribute('ylabel'),
        yformat = canvas.getAttribute('yformat'),
        yrange = canvas.getAttribute('yrange'),
        xlabel = canvas.getAttribute('xlabel'),
        xformat = canvas.getAttribute('xformat'),
        xlog = canvas.getAttribute('xlog');
        grid = canvas.getAttribute('grid');


	// Defaults
	if (ylabel  === null) { ylabel  = ""; }
    if (xlabel  === null) { xlabel  = ""; }
    if (xlog    === null) { xlog    = false; }
	if (grid    === null) { grid    = true; }

	var margin = {top: 20, right: 20, bottom: 40, left: 80},
	    width = canvas.width - margin.left - margin.right,
	    height = canvas.height - margin.top - margin.bottom;

	var x = (xlog ? d3.scaleLog() : d3.scaleLinear())
	    .range([0, width]);

	var y = d3.scaleLinear()
	    .range([height, 0]);

	var line = d3.line()
	    .x(function(d) { return x(d.count); })
	    .y(function(d) { return y(d.frac); })
	    .curve(d3.curveLinear)  //curveStep, curveLinear, curveNatural?
	    .context(context);

	context.translate(margin.left, margin.top);

	d3.csv({{ path|tojson|safe }}, function(d) {
	  d.count = +d.count;	// parseInt?
	  d.frac = parseFloat(d.frac);
	  return d;
	}).then(function(data) {
	  x.domain(d3.extent(data, function(d) { return d.count; }));
	  y.domain(d3.extent(data, function(d) { return d.frac; }));

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


        if (xformat != null) {
            if (xformat.startsWith("logfmt:")) {
                tickFormat = function(t) {
                    if (x.tickFormat()(t) == "") { return ""; }
                    return d3.format(xformat.split(':')[1])(t)
                };
            } else {
                tickFormat = x.tickFormat(d3.format(xformat));
            }
        }

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

      context.save();
      context.font = "bold 10pt sans-serif";
      context.textAlign = "right";
      context.textBaseline = "bottom";
      context.fillText(xlabel, width - tickSize, height - tickSize);
      context.restore();

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


})();
