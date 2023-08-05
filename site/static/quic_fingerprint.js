function recursiveRequest(retry) {
    if (retry <= 0) {
        $('#your-browser-no-quic').show();
        return;
    }
    $.get('https://quic.tlsfingerprint.io/qfp/', function (data) {
        if (data.hasOwnProperty("cip_fp_id")) {
            console.log(data);
            hdrid = data.quic_header.hdrid;
            chid = data.quic_client_hello.id;
            chnormid = data.quic_client_hello.norm_id;
            qtpid = data.quic_transport_parameters.tpfpid;
            cipid = data.cip_fp_id;

            url = '/id/' + cipid;
            $('#id').attr('href', url);
            $('#id').text(cipid);
            hdrurl = '/qid/' + hdrid;
            $('#qid').attr('href', hdrurl);
            $('#qid').text(hdrid);
            turl = '/tid/' + chnormid;
            $('#tid').attr('href', turl);
            $('#tid').text(chnormid);
            qtpurl = '/qtp/' + qtpid;
            $('#qtp').attr('href', qtpurl);
            $('#qtp').text(qtpid);
            $('#your-browser').show();
        }
        else {
            console.log("retry getting QUIC fingerprint...");
            recursiveRequest(retry-1);
        }
    });
}

$(function() {
   recursiveRequest(3);
});