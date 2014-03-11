mincointools.wallets.instructions = {
    open: function () {
        document.getElementById("instructionsarea").style.display = "block";
    },

    close: function () {
        document.getElementById("instructionsarea").style.display = "none";
    },

    viewDetails: function () {

    },

    populateKeyDetails: function (btcKey) {

    },

    clear: function () {
        document.getElementById("detailpubkey").innerHTML = "";
        document.getElementById("detailpubkeycomp").innerHTML = "";
        document.getElementById("detailaddress").innerHTML = "";
        document.getElementById("detailaddresscomp").innerHTML = "";
        document.getElementById("detailprivwif").innerHTML = "";
        document.getElementById("detailprivwifcomp").innerHTML = "";
        document.getElementById("detailprivhex").innerHTML = "";
        document.getElementById("detailprivb64").innerHTML = "";
        document.getElementById("detailprivmini").innerHTML = "";
        document.getElementById("detailqrcodepublic").innerHTML = "";
        document.getElementById("detailqrcodepubliccomp").innerHTML = "";
        document.getElementById("detailqrcodeprivate").innerHTML = "";
        document.getElementById("detailqrcodeprivatecomp").innerHTML = "";
        document.getElementById("detailbip38commands").style.display = "none";
    }
}