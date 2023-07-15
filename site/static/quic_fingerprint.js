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

            url = '/qid/' + cipid;
            $('#fp-url').attr('href', url);
            $('#fp-url').text(cipid);
            $('#quic-hdr').text(hdrid);
            $('#quic-ch').text(chid);
            $('#quic-ch-norm').text(chnormid);
            $('#quic-tp').text(qtpid);
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