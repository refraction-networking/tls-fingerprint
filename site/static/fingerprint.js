$(function() {
    $.get('https://client.tlsfingerprint.io.gauk.as/', function (data) {
        url = '/id/' + data.id;
        norm_url = '/id/N/' + data.norm_id;

        console.log("data.id: " + data.id);
        console.log("data.norm_id: " + data.norm_id);

        $.get('get-fp-stats?normid='+data.norm_id, function (stats) {
            rank = stats.rank;
            pct = Math.round(stats.frac_seen*100*100)/100;

            $('#fp-url').attr('href', url);
            $('#fp-url').text(data.id);
            $('#norm-fp-url').attr('href', norm_url);
            $('#norm-fp-url').text('N/'+data.norm_id);
            $('#fp-pct').text(pct);
            $('#fp-rank').text(rank);
            $('#your-browser').show();
        });

        $.post('add-user-agent', {useragent: data.user_agent, id: data.id, normid: data.norm_id}, function(result){
            console.log(result);
        });
    });
});
