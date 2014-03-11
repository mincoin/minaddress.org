// run unit tests
if (mincointools.getQueryString()["unittests"] == "true" || mincointools.getQueryString()["unittests"] == "1") {
	mincointools.unitTests.runSynchronousTests();
	mincointools.translator.showEnglishJson();
}
// run async unit tests
if (mincointools.getQueryString()["asyncunittests"] == "true" || mincointools.getQueryString()["asyncunittests"] == "1") {
	mincointools.unitTests.runAsynchronousTests();
}
// change language
if (mincointools.getQueryString()["culture"] != undefined) {
	mincointools.translator.translate(mincointools.getQueryString()["culture"]);
}
// testnet, check if testnet edition should be activated
if (mincointools.getQueryString()["testnet"] == "true" || mincointools.getQueryString()["testnet"] == "1") {
	document.getElementById("testnet").innerHTML = mincointools.translator.get("testneteditionactivated");
	document.getElementById("testnet").style.display = "block";
	document.getElementById("detailwifprefix").innerHTML = "'9'";
	document.getElementById("detailcompwifprefix").innerHTML = "'c'";
	Bitcoin.Address.networkVersion = 0x6F; // testnet
	Bitcoin.ECKey.privateKeyPrefix = 0xEF; // testnet
	mincointools.testnetMode = true;
}
// if users does not move mouse after random amount of time then generate the key anyway.
setTimeout(mincointools.seeder.forceGenerate, mincointools.seeder.seedLimit * 20);