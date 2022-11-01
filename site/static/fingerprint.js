

$(function() {
    $.get('https://client.tlsfingerprint.io:8443/', function (data) {
        url = '/id/' + data.id;
        rank = data.rank;
        pct = Math.round(data.frac_seen*100*100)/100;
        cluster_pct = Math.round(data.cluster_frac*100*100)/100;

        $('#fp-url').attr('href', url);
        $('#fp-url').text(data.id);
        $('#fp-pct').text(pct);
        $('#fp-rank').text(rank);
        if (data.cluster_seen > 0) {
            $('#fp-cluster').text(data.cluster);
            $('#fp-cluster-url').attr('href', '/cluster/' + data.id);
            $('#fp-cluster-span').show();
        }
        $('#your-browser').show();
    });
});
