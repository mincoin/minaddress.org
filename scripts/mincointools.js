var mincointools = { wallets: {} };

mincointools.privateKey = {
    isPrivateKey: function (key) {
        return (
            Bitcoin.ECKey.isWalletImportFormat(key) ||
                Bitcoin.ECKey.isCompressedWalletImportFormat(key) ||
                Bitcoin.ECKey.isHexFormat(key) ||
                Bitcoin.ECKey.isBase64Format(key) ||
                Bitcoin.ECKey.isMiniFormat(key)
            );
    },
    getECKeyFromAdding: function (privKey1, privKey2) {
        var n = EllipticCurve.getSECCurveByName("secp256k1").getN();
        var ecKey1 = new Bitcoin.ECKey(privKey1);
        var ecKey2 = new Bitcoin.ECKey(privKey2);
        // if both keys are the same return null
        if (ecKey1.getBitcoinHexFormat() == ecKey2.getBitcoinHexFormat()) return null;
        if (ecKey1 == null || ecKey2 == null) return null;
        var combinedPrivateKey = new Bitcoin.ECKey(ecKey1.priv.add(ecKey2.priv).mod(n));
        // compressed when both keys are compressed
        if (ecKey1.compressed && ecKey2.compressed) combinedPrivateKey.setCompressed(true);
        return combinedPrivateKey;
    },
    getECKeyFromMultiplying: function (privKey1, privKey2) {
        var n = EllipticCurve.getSECCurveByName("secp256k1").getN();
        var ecKey1 = new Bitcoin.ECKey(privKey1);
        var ecKey2 = new Bitcoin.ECKey(privKey2);
        // if both keys are the same return null
        if (ecKey1.getBitcoinHexFormat() == ecKey2.getBitcoinHexFormat()) return null;
        if (ecKey1 == null || ecKey2 == null) return null;
        var combinedPrivateKey = new Bitcoin.ECKey(ecKey1.priv.multiply(ecKey2.priv).mod(n));
        // compressed when both keys are compressed
        if (ecKey1.compressed && ecKey2.compressed) combinedPrivateKey.setCompressed(true);
        return combinedPrivateKey;
    },
    // 58 base58 characters starting with 6P
    isBIP38Format: function (key) {
        key = key.toString();
        return (/^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(key));
    },
    BIP38EncryptedKeyToByteArrayAsync: function (base58Encrypted, passphrase, callback) {
        var hex;
        try {
            hex = Bitcoin.Base58.decode(base58Encrypted);
        } catch (e) {
            callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
            return;
        }

        // 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
        if (hex.length != 43) {
            callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
            return;
        }
        // first byte is always 0x01
        else if (hex[0] != 0x01) {
            callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
            return;
        }

        var expChecksum = hex.slice(-4);
        hex = hex.slice(0, -4);
        var checksum = Bitcoin.Util.dsha256(hex);
        if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
            callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
            return;
        }

        var isCompPoint = false;
        var isECMult = false;
        var hasLotSeq = false;
        // second byte for non-EC-multiplied key
        if (hex[1] == 0x42) {
            // key should use compression
            if (hex[2] == 0xe0) {
                isCompPoint = true;
            }
            // key should NOT use compression
            else if (hex[2] != 0xc0) {
                callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
                return;
            }
        }
        // second byte for EC-multiplied key
        else if (hex[1] == 0x43) {
            isECMult = true;
            isCompPoint = (hex[2] & 0x20) != 0;
            hasLotSeq = (hex[2] & 0x04) != 0;
            if ((hex[2] & 0x24) != hex[2]) {
                callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
                return;
            }
        }
        else {
            callback(new Error(mincointools.translator.get("detailalertnotvalidprivatekey")));
            return;
        }

        var decrypted;
        var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

        var verifyHashAndReturn = function () {
            var tmpkey = new Bitcoin.ECKey(decrypted); // decrypted using closure
            var base58AddrText = tmpkey.setCompressed(isCompPoint).getBitcoinAddress(); // isCompPoint using closure
            checksum = Bitcoin.Util.dsha256(base58AddrText); // checksum using closure

            if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
                callback(new Error(mincointools.translator.get("bip38alertincorrectpassphrase"))); // callback using closure
                return;
            }
            callback(tmpkey.getBitcoinPrivateKeyByteArray()); // callback using closure
        };

        if (!isECMult) {
            var addresshash = hex.slice(3, 7);
            Crypto_scrypt(passphrase, addresshash, 16384, 8, 8, 64, function (derivedBytes) {
                var k = derivedBytes.slice(32, 32 + 32);
                decrypted = Crypto.AES.decrypt(hex.slice(7, 7 + 32), k, AES_opts);
                for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
                verifyHashAndReturn(); //TODO: pass in 'decrypted' as a param
            });
        }
        else {
            var ownerentropy = hex.slice(7, 7 + 8);
            var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
            Crypto_scrypt(passphrase, ownersalt, 16384, 8, 8, 32, function (prefactorA) {
                var passfactor;
                if (!hasLotSeq) { // hasLotSeq using closure
                    passfactor = prefactorA;
                } else {
                    var prefactorB = prefactorA.concat(ownerentropy); // ownerentropy using closure
                    passfactor = Bitcoin.Util.dsha256(prefactorB);
                }
                var kp = new Bitcoin.ECKey(passfactor);
                var passpoint = kp.setCompressed(true).getPub();

                var encryptedpart2 = hex.slice(23, 23 + 16);

                var addresshashplusownerentropy = hex.slice(3, 3 + 12);
                Crypto_scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64, function (derived) {
                    var k = derived.slice(32);

                    var unencryptedpart2 = Crypto.AES.decrypt(encryptedpart2, k, AES_opts);
                    for (var i = 0; i < 16; i++) { unencryptedpart2[i] ^= derived[i + 16]; }

                    var encryptedpart1 = hex.slice(15, 15 + 8).concat(unencryptedpart2.slice(0, 0 + 8));
                    var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
                    for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }

                    var seedb = unencryptedpart1.slice(0, 0 + 16).concat(unencryptedpart2.slice(8, 8 + 8));

                    var factorb = Bitcoin.Util.dsha256(seedb);

                    var ps = EllipticCurve.getSECCurveByName("secp256k1");
                    var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ps.getN());

                    decrypted = privateKey.toByteArrayUnsigned();
                    verifyHashAndReturn();
                });
            });
        }
    },
    BIP38PrivateKeyToEncryptedKeyAsync: function (base58Key, passphrase, compressed, callback) {
        var privKey = new Bitcoin.ECKey(base58Key);
        var privKeyBytes = privKey.getBitcoinPrivateKeyByteArray();
        var address = privKey.setCompressed(compressed).getBitcoinAddress();

        // compute sha256(sha256(address)) and take first 4 bytes
        var salt = Bitcoin.Util.dsha256(address).slice(0, 4);

        // derive key using scrypt
        var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

        Crypto_scrypt(passphrase, salt, 16384, 8, 8, 64, function (derivedBytes) {
            for (var i = 0; i < 32; ++i) {
                privKeyBytes[i] ^= derivedBytes[i];
            }

            // 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
            var flagByte = compressed ? 0xe0 : 0xc0;
            var encryptedKey = [0x01, 0x42, flagByte].concat(salt);
            encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), AES_opts));
            encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0, 4));
            callback(Bitcoin.Base58.encode(encryptedKey));
        });
    },
    BIP38GenerateIntermediatePointAsync: function (passphrase, lotNum, sequenceNum, callback) {
        var noNumbers = lotNum === null || sequenceNum === null;
        var rng = new SecureRandom();
        var ownerEntropy, ownerSalt;

        if (noNumbers) {
            ownerSalt = ownerEntropy = new Array(8);
            rng.nextBytes(ownerEntropy);
        }
        else {
            // 1) generate 4 random bytes
            ownerSalt = new Array(4);

            rng.nextBytes(ownerSalt);

            // 2)  Encode the lot and sequence numbers as a 4 byte quantity (big-endian):
            // lotnumber * 4096 + sequencenumber. Call these four bytes lotsequence.
            var lotSequence = BigInteger(4096 * lotNum + sequenceNum).toByteArrayUnsigned();

            // 3) Concatenate ownersalt + lotsequence and call this ownerentropy.
            var ownerEntropy = ownerSalt.concat(lotSequence);
        }


        // 4) Derive a key from the passphrase using scrypt
        Crypto_scrypt(passphrase, ownerSalt, 16384, 8, 8, 32, function (prefactor) {
            // Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
            var passfactorBytes = noNumbers ? prefactor : Bitcoin.Util.dsha256(prefactor.concat(ownerEntropy));
            var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);

            // 5) Compute the elliptic curve point G * passfactor, and convert the result to compressed notation (33 bytes)
            var ellipticCurve = EllipticCurve.getSECCurveByName("secp256k1");
            var passpoint = ellipticCurve.getG().multiply(passfactor).getEncoded(1);

            // 6) Convey ownersalt and passpoint to the party generating the keys, along with a checksum to ensure integrity.
            // magic bytes "2C E9 B3 E1 FF 39 E2 51" followed by ownerentropy, and then passpoint
            var magicBytes = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];
            if (noNumbers) magicBytes[7] = 0x53;

            var intermediate = magicBytes.concat(ownerEntropy).concat(passpoint);

            // base58check encode
            intermediate = intermediate.concat(Bitcoin.Util.dsha256(intermediate).slice(0, 4));
            callback(Bitcoin.Base58.encode(intermediate));
        });
    },
    BIP38GenerateECAddressAsync: function (intermediate, compressed, callback) {
        // decode IPS
        var x = Bitcoin.Base58.decode(intermediate);
        //if(x.slice(49, 4) !== Bitcoin.Util.dsha256(x.slice(0,49)).slice(0,4)) {
        //	callback({error: 'Invalid intermediate passphrase string'});
        //}
        var noNumbers = (x[7] === 0x53);
        var ownerEntropy = x.slice(8, 8 + 8);
        var passpoint = x.slice(16, 16 + 33);

        // 1) Set flagbyte.
        // set bit 0x20 for compressed key
        // set bit 0x04 if ownerentropy contains a value for lotsequence
        var flagByte = (compressed ? 0x20 : 0x00) | (noNumbers ? 0x00 : 0x04);


        // 2) Generate 24 random bytes, call this seedb.
        var seedB = new Array(24);
        var rng = new SecureRandom();
        rng.nextBytes(seedB);

        // Take SHA256(SHA256(seedb)) to yield 32 bytes, call this factorb.
        var factorB = Bitcoin.Util.dsha256(seedB);

        // 3) ECMultiply passpoint by factorb. Use the resulting EC point as a public key and hash it into a Bitcoin
        // address using either compressed or uncompressed public key methodology (specify which methodology is used
        // inside flagbyte). This is the generated Bitcoin address, call it generatedaddress.
        var ec = EllipticCurve.getSECCurveByName("secp256k1").getCurve();
        var generatedPoint = ec.decodePointHex(mincointools.publicKey.getHexFromByteArray(passpoint));
        var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(compressed);
        var generatedAddress = (new Bitcoin.Address(Bitcoin.Util.sha256ripe160(generatedBytes))).toString();

        // 4) Take the first four bytes of SHA256(SHA256(generatedaddress)) and call it addresshash.
        var addressHash = Bitcoin.Util.dsha256(generatedAddress).slice(0, 4);

        // 5) Now we will encrypt seedb. Derive a second key from passpoint using scrypt
        Crypto_scrypt(passpoint, addressHash.concat(ownerEntropy), 1024, 1, 1, 64, function (derivedBytes) {
            // 6) Do AES256Encrypt(seedb[0...15]] xor derivedhalf1[0...15], derivedhalf2), call the 16-byte result encryptedpart1
            for (var i = 0; i < 16; ++i) {
                seedB[i] ^= derivedBytes[i];
            }
            var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };
            var encryptedPart1 = Crypto.AES.encrypt(seedB.slice(0, 16), derivedBytes.slice(32), AES_opts);

            // 7) Do AES256Encrypt((encryptedpart1[8...15] + seedb[16...23]) xor derivedhalf1[16...31], derivedhalf2), call the 16-byte result encryptedseedb.
            var message2 = encryptedPart1.slice(8, 8 + 8).concat(seedB.slice(16, 16 + 8));
            for (var i = 0; i < 16; ++i) {
                message2[i] ^= derivedBytes[i + 16];
            }
            var encryptedSeedB = Crypto.AES.encrypt(message2, derivedBytes.slice(32), AES_opts);

            // 0x01 0x43 + flagbyte + addresshash + ownerentropy + encryptedpart1[0...7] + encryptedpart2
            var encryptedKey = [0x01, 0x43, flagByte].concat(addressHash).concat(ownerEntropy).concat(encryptedPart1.slice(0, 8)).concat(encryptedSeedB);

            // base58check encode
            encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0, 4));
            callback(generatedAddress, Bitcoin.Base58.encode(encryptedKey));
        });
    }
};

mincointools.publicKey = {
    isPublicKeyHexFormat: function (key) {
        key = key.toString();
        return mincointools.publicKey.isUncompressedPublicKeyHexFormat(key) || mincointools.publicKey.isCompressedPublicKeyHexFormat(key);
    },
    // 130 characters [0-9A-F] starts with 04
    isUncompressedPublicKeyHexFormat: function (key) {
        key = key.toString();
        return /^04[A-Fa-f0-9]{128}$/.test(key);
    },
    // 66 characters [0-9A-F] starts with 02 or 03
    isCompressedPublicKeyHexFormat: function (key) {
        key = key.toString();
        return /^0[2-3][A-Fa-f0-9]{64}$/.test(key);
    },
    getBitcoinAddressFromByteArray: function (pubKeyByteArray) {
        var pubKeyHash = Bitcoin.Util.sha256ripe160(pubKeyByteArray);
        var addr = new Bitcoin.Address(pubKeyHash);
        return addr.toString();
    },
    getHexFromByteArray: function (pubKeyByteArray) {
        return Crypto.util.bytesToHex(pubKeyByteArray).toString().toUpperCase();
    },
    getByteArrayFromAdding: function (pubKeyHex1, pubKeyHex2) {
        var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
        var curve = ecparams.getCurve();
        var ecPoint1 = curve.decodePointHex(pubKeyHex1);
        var ecPoint2 = curve.decodePointHex(pubKeyHex2);
        // if both points are the same return null
        if (ecPoint1.equals(ecPoint2)) return null;
        var compressed = (ecPoint1.compressed && ecPoint2.compressed);
        var pubKey = ecPoint1.add(ecPoint2).getEncoded(compressed);
        return pubKey;
    },
    getByteArrayFromMultiplying: function (pubKeyHex, ecKey) {
        var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
        var ecPoint = ecparams.getCurve().decodePointHex(pubKeyHex);
        var compressed = (ecPoint.compressed && ecKey.compressed);
        // if both points are the same return null
        ecKey.setCompressed(false);
        if (ecPoint.equals(ecKey.getPubPoint())) {
            return null;
        }
        var bigInt = ecKey.priv;
        var pubKey = ecPoint.multiply(bigInt).getEncoded(compressed);
        return pubKey;
    },
    // used by unit test
    getDecompressedPubKeyHex: function (pubKeyHexComp) {
        var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
        var ecPoint = ecparams.getCurve().decodePointHex(pubKeyHexComp);
        var pubByteArray = ecPoint.getEncoded(0);
        var pubHexUncompressed = mincointools.publicKey.getHexFromByteArray(pubByteArray);
        return pubHexUncompressed;
    }
};

mincointools.wallets.bulkwallet = {
	open: function () {
		document.getElementById("bulkarea").style.display = "block";
		// show a default CSV list if the text area is empty
		if (document.getElementById("bulktextarea").value == "") {
			// return control of the thread to the browser to render the tab switch UI then build a default CSV list
			setTimeout(function () { mincointools.wallets.bulkwallet.buildCSV(3, 1, false); }, 200);
		}
	},

	close: function () {
		document.getElementById("bulkarea").style.display = "none";
	},

	// use this function to bulk generate addresses
	// rowLimit: number of Bitcoin Addresses to generate
	// startIndex: add this number to the row index for output purposes
	// returns:
	// index,bitcoinAddress,privateKeyWif
	buildCSV: function (rowLimit, startIndex, compressedAddrs) {
		var bulkWallet = mincointools.wallets.bulkwallet;
		document.getElementById("bulktextarea").value = mincointools.translator.get("bulkgeneratingaddresses") + rowLimit;
		bulkWallet.csv = [];
		bulkWallet.csvRowLimit = rowLimit;
		bulkWallet.csvRowsRemaining = rowLimit;
		bulkWallet.csvStartIndex = --startIndex;
		bulkWallet.compressedAddrs = !!compressedAddrs;
		setTimeout(bulkWallet.batchCSV, 0);
	},

	csv: [],
	csvRowsRemaining: null, // use to keep track of how many rows are left to process when building a large CSV array
	csvRowLimit: 0,
	csvStartIndex: 0,

	batchCSV: function () {
		var bulkWallet = mincointools.wallets.bulkwallet;
		if (bulkWallet.csvRowsRemaining > 0) {
			bulkWallet.csvRowsRemaining--;
			var key = new Bitcoin.ECKey(false);
			key.setCompressed(bulkWallet.compressedAddrs);

			bulkWallet.csv.push((bulkWallet.csvRowLimit - bulkWallet.csvRowsRemaining + bulkWallet.csvStartIndex)
								+ ",\"" + key.getBitcoinAddress() + "\",\"" + key.toString("wif")
			//+	"\",\"" + key.toString("wifcomp")    // uncomment these lines to add different private key formats to the CSV
			//+ "\",\"" + key.getBitcoinHexFormat() 
			//+ "\",\"" + key.toString("base64") 
								+ "\"");

			document.getElementById("bulktextarea").value = mincointools.translator.get("bulkgeneratingaddresses") + bulkWallet.csvRowsRemaining;

			// release thread to browser to render UI
			setTimeout(bulkWallet.batchCSV, 0);
		}
		// processing is finished so put CSV in text area
		else if (bulkWallet.csvRowsRemaining === 0) {
			document.getElementById("bulktextarea").value = bulkWallet.csv.join("\n");
		}
	},

	openCloseFaq: function (faqNum) {
		// do close
		if (document.getElementById("bulka" + faqNum).style.display == "block") {
			document.getElementById("bulka" + faqNum).style.display = "none";
			document.getElementById("bulke" + faqNum).setAttribute("class", "more");
		}
		// do open
		else {
			document.getElementById("bulka" + faqNum).style.display = "block";
			document.getElementById("bulke" + faqNum).setAttribute("class", "less");
		}
	}
};

mincointools.wallets.detailwallet = {
    open: function () {
        document.getElementById("detailarea").style.display = "block";
        document.getElementById("detailprivkey").focus();
    },

    close: function () {
        document.getElementById("detailarea").style.display = "none";
    },

    viewDetails: function () {
        var bip38 = false;
        var key = document.getElementById("detailprivkey").value.toString().replace(/^\s+|\s+$/g, ""); // trim white space
        if (key == "") {
            mincointools.wallets.detailwallet.clear();
            return;
        }
        document.getElementById("detailprivkey").value = key;
        if (Bitcoin.ECKey.isMiniFormat(key)) {
            // show Private Key Mini Format
            document.getElementById("detailprivmini").innerHTML = key;
            document.getElementById("detailmini").style.display = "block";
            document.getElementById("detailbip38commands").style.display = "none";
        }
        else if (mincointools.privateKey.isBIP38Format(key)) {
            if (document.getElementById("detailbip38commands").style.display != "block") {
                document.getElementById("detailbip38commands").style.display = "block";
                document.getElementById("detailprivkeypassphrase").focus();
                return;
            }
            else {
                bip38 = true;
            }
        }
        else {
            // hide Private Key Mini Format
            document.getElementById("detailmini").style.display = "none";
            document.getElementById("detailbip38commands").style.display = "none";
        }

        if (bip38) {
            var passphrase = document.getElementById("detailprivkeypassphrase").value.toString().replace(/^\s+|\s+$/g, ""); // trim white space
            if (passphrase == "") {
                alert(mincointools.translator.get("bip38alertpassphraserequired"));
                return;
            }
            mincointools.privateKey.BIP38EncryptedKeyToByteArrayAsync(key, passphrase, function (btcKeyOrError) {
                document.getElementById("busyblock").className = "";
                if (btcKeyOrError.message) {
                    alert(btcKeyOrError.message);
                    mincointools.wallets.detailwallet.clear();
                } else {
                    mincointools.wallets.detailwallet.populateKeyDetails(new Bitcoin.ECKey(btcKeyOrError));
                }
            });
            document.getElementById("busyblock").className = "busy";
        }
        else {
            var btcKey = new Bitcoin.ECKey(key);
            if (btcKey.priv == null) {
                // enforce a minimum passphrase length
                if (key.length >= mincointools.wallets.brainwallet.minPassphraseLength) {
                    // Deterministic Wallet confirm box to ask if user wants to SHA256 the input to get a private key
                    var usePassphrase = confirm(mincointools.translator.get("detailconfirmsha256"));
                    if (usePassphrase) {
                        var bytes = Crypto.SHA256(key, { asBytes: true });
                        var btcKey = new Bitcoin.ECKey(bytes);
                    }
                    else {
                        mincointools.wallets.detailwallet.clear();
                    }
                }
                else {
                    alert(mincointools.translator.get("detailalertnotvalidprivatekey"));
                    mincointools.wallets.detailwallet.clear();
                }
            }
            mincointools.wallets.detailwallet.populateKeyDetails(btcKey);
        }
    },

    populateKeyDetails: function (btcKey) {
        if (btcKey.priv != null) {
            btcKey.setCompressed(false);
            document.getElementById("detailprivhex").innerHTML = btcKey.toString().toUpperCase();
            document.getElementById("detailprivb64").innerHTML = btcKey.toString("base64");
            var bitcoinAddress = btcKey.getBitcoinAddress();
            var wif = btcKey.getBitcoinWalletImportFormat();
            document.getElementById("detailpubkey").innerHTML = btcKey.getPubKeyHex();
            document.getElementById("detailaddress").innerHTML = bitcoinAddress;
            document.getElementById("detailprivwif").innerHTML = wif;
            btcKey.setCompressed(true);
            var bitcoinAddressComp = btcKey.getBitcoinAddress();
            var wifComp = btcKey.getBitcoinWalletImportFormat();
            document.getElementById("detailpubkeycomp").innerHTML = btcKey.getPubKeyHex();
            document.getElementById("detailaddresscomp").innerHTML = bitcoinAddressComp;
            document.getElementById("detailprivwifcomp").innerHTML = wifComp;

            mincointools.qrCode.showQrCode({
                "detailqrcodepublic": bitcoinAddress,
                "detailqrcodepubliccomp": bitcoinAddressComp,
                "detailqrcodeprivate": wif,
                "detailqrcodeprivatecomp": wifComp
            }, 4);
        }
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
};

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

mincointools.seeder = {
    // number of mouse movements to wait for
    seedLimit: (function () {
        var num = Crypto.util.randomBytes(12)[11];
        return 50 + Math.floor(num);
    })(),

    seedCount: 0, // counter

    // seed function exists to wait for mouse movement to add more entropy before generating an address
    seed: function (evt) {
        if (!evt) var evt = window.event;

        // seed a bunch (minimum seedLimit) of times based on mouse moves
        SecureRandom.seedTime();
        // seed mouse position X and Y
        if (evt) SecureRandom.seedInt((evt.clientX * evt.clientY));

        mincointools.seeder.seedCount++;
        // seeding is over now we generate and display the address
        if (mincointools.seeder.seedCount == mincointools.seeder.seedLimit) {
            mincointools.wallets.singlewallet.open();
            // UI
            document.getElementById("generate").style.display = "none";
            document.getElementById("menu").style.visibility = "visible";
        }
    },

    // If user has not moved the mouse or if they are on a mobile device
    // we will force the generation after a random period of time.
    forceGenerate: function () {
        // if the mouse has not moved enough
        if (mincointools.seeder.seedCount < mincointools.seeder.seedLimit) {
            SecureRandom.seedTime();
            mincointools.seeder.seedCount = mincointools.seeder.seedLimit - 1;
            mincointools.seeder.seed();
        }
    }
};

mincointools.qrCode = {
    // determine which type number is big enough for the input text length
    getTypeNumber: function (text) {
        var lengthCalculation = text.length * 8 + 12; // length as calculated by the QRCode
        if (lengthCalculation < 72) { return 1; }
        else if (lengthCalculation < 128) { return 2; }
        else if (lengthCalculation < 208) { return 3; }
        else if (lengthCalculation < 288) { return 4; }
        else if (lengthCalculation < 368) { return 5; }
        else if (lengthCalculation < 480) { return 6; }
        else if (lengthCalculation < 528) { return 7; }
        else if (lengthCalculation < 688) { return 8; }
        else if (lengthCalculation < 800) { return 9; }
        else if (lengthCalculation < 976) { return 10; }
        return null;
    },

    createCanvas: function (text, sizeMultiplier) {
        sizeMultiplier = (sizeMultiplier == undefined) ? 4 : sizeMultiplier; // default 2
        // create the qrcode itself
        var typeNumber = mincointools.qrCode.getTypeNumber(text);
        var qrcode = new QRCode(typeNumber, QRCode.ErrorCorrectLevel.H);
        qrcode.addData(text);
        qrcode.make();
        var width = qrcode.getModuleCount() * sizeMultiplier;
        var height = qrcode.getModuleCount() * sizeMultiplier;
        // create canvas element
        var canvas = document.createElement('canvas');
        var scale = 10.0;
        canvas.width = width * scale;
        canvas.height = height * scale;
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';
        var ctx = canvas.getContext('2d');
        ctx.scale(scale, scale);
        // compute tileW/tileH based on width/height
        var tileW = width / qrcode.getModuleCount();
        var tileH = height / qrcode.getModuleCount();
        // draw in the canvas
        for (var row = 0; row < qrcode.getModuleCount(); row++) {
            for (var col = 0; col < qrcode.getModuleCount(); col++) {
                ctx.fillStyle = qrcode.isDark(row, col) ? "#000000" : "#ffffff";
                ctx.fillRect(col * tileW, row * tileH, tileW, tileH);
            }
        }
        // return just built canvas
        return canvas;
    },

    // generate a QRCode and return it's representation as an Html table
    createTableHtml: function (text) {
        var typeNumber = mincointools.qrCode.getTypeNumber(text);
        var qr = new QRCode(typeNumber, QRCode.ErrorCorrectLevel.H);
        qr.addData(text);
        qr.make();
        var tableHtml = "<table class='qrcodetable'>";
        for (var r = 0; r < qr.getModuleCount(); r++) {
            tableHtml += "<tr>";
            for (var c = 0; c < qr.getModuleCount(); c++) {
                if (qr.isDark(r, c)) {
                    tableHtml += "<td class='qrcodetddark'/>";
                } else {
                    tableHtml += "<td class='qrcodetdlight'/>";
                }
            }
            tableHtml += "</tr>";
        }
        tableHtml += "</table>";
        return tableHtml;
    },

    // show QRCodes with canvas OR table (IE8)
    // parameter: keyValuePair
    // example: { "id1": "string1", "id2": "string2"}
    //		"id1" is the id of a div element where you want a QRCode inserted.
    //		"string1" is the string you want encoded into the QRCode.
    showQrCode: function (keyValuePair, sizeMultiplier) {
        for (var key in keyValuePair) {
            var value = keyValuePair[key];
            try {
                if (document.getElementById(key)) {
                    document.getElementById(key).innerHTML = "";
                    document.getElementById(key).appendChild(mincointools.qrCode.createCanvas(value, sizeMultiplier));
                }
            }
            catch (e) {
                // for browsers that do not support canvas (IE8)
                document.getElementById(key).innerHTML = mincointools.qrCode.createTableHtml(value);
            }
        }
    }
};

mincointools.tabSwitch = function (walletTab) {
    if (walletTab.className.indexOf("selected") == -1) {
        // unselect all tabs
        for (var wType in mincointools.wallets) {
            document.getElementById(wType).className = "tab";
            mincointools.wallets[wType].close();
        }
        walletTab.className += " selected";
        mincointools.wallets[walletTab.getAttribute("id")].open();
    }
};

mincointools.getQueryString = function () {
    var result = {}, queryString = location.search.substring(1), re = /([^&=]+)=([^&]*)/g, m;
    while (m = re.exec(queryString)) {
        result[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
    }
    return result;
};

// use when passing an Array of Functions
mincointools.runSerialized = function (functions, onComplete) {
    onComplete = onComplete || function () { };

    if (functions.length === 0) onComplete();
    else {
        // run the first function, and make it call this
        // function when finished with the rest of the list
        var f = functions.shift();
        f(function () { mincointools.runSerialized(functions, onComplete); });
    }
};

mincointools.forSerialized = function (initial, max, whatToDo, onComplete) {
    onComplete = onComplete || function () { };

    if (initial === max) { onComplete(); }
    else {
        // same idea as runSerialized
        whatToDo(initial, function () { mincointools.forSerialized(++initial, max, whatToDo, onComplete); });
    }
};

// use when passing an Object (dictionary) of Functions
mincointools.foreachSerialized = function (collection, whatToDo, onComplete) {
    var keys = [];
    for (var name in collection) {
        keys.push(name);
    }
    mincointools.forSerialized(0, keys.length, function (i, callback) {
        whatToDo(keys[i], callback);
    }, onComplete);
};

mincointools.wallets.paperwallet = {
    open: function () {
        $("main").attr("class", "paper"); // add 'paper' class to main div
        var paperArea = document.getElementById("paperarea");
        paperArea.style.display = "block";
        var perPageLimitElement = document.getElementById("paperlimitperpage");
        var limitElement = document.getElementById("paperlimit");
        var pageBreakAt = (mincointools.wallets.paperwallet.useArtisticWallet) ? mincointools.wallets.paperwallet.pageBreakAtArtisticDefault : mincointools.wallets.paperwallet.pageBreakAtDefault;
        if (perPageLimitElement && perPageLimitElement.value < 1) {
            perPageLimitElement.value = pageBreakAt;
        }
        if (limitElement && limitElement.value < 1) {
            limitElement.value = pageBreakAt;
        }
        if (document.getElementById("paperkeyarea").innerHTML == "") {
            document.getElementById("paperpassphrase").disabled = true;
            document.getElementById("paperencrypt").checked = false;
            mincointools.wallets.paperwallet.encrypt = false;
            mincointools.wallets.paperwallet.build(pageBreakAt, pageBreakAt, !document.getElementById('paperart').checked, document.getElementById('paperpassphrase').value);
        }
    },

    close: function () {
        document.getElementById("paperarea").style.display = "none";
        $("main").attr("class", ""); // remove 'paper' class from main div
    },

    remaining: null, // use to keep track of how many addresses are left to process when building the paper wallet
    count: 0,
    pageBreakAtDefault: 7,
    pageBreakAtArtisticDefault: 3,
    useArtisticWallet: true,
    pageBreakAt: null,

    build: function (numWallets, pageBreakAt, useArtisticWallet, passphrase) {
        if (numWallets < 1) numWallets = 1;
        if (pageBreakAt < 1) pageBreakAt = 1;
        mincointools.wallets.paperwallet.remaining = numWallets;
        mincointools.wallets.paperwallet.count = 0;
        mincointools.wallets.paperwallet.useArtisticWallet = useArtisticWallet;
        mincointools.wallets.paperwallet.pageBreakAt = pageBreakAt;
        document.getElementById("paperkeyarea").innerHTML = "";
        if (mincointools.wallets.paperwallet.encrypt) {
            document.getElementById("busyblock").className = "busy";
            mincointools.privateKey.BIP38GenerateIntermediatePointAsync(passphrase, null, null, function (intermediate) {
                mincointools.wallets.paperwallet.intermediatePoint = intermediate;
                document.getElementById("busyblock").className = "";
                setTimeout(mincointools.wallets.paperwallet.batch, 0);
            });
        }
        else {
            setTimeout(mincointools.wallets.paperwallet.batch, 0);
        }
    },

    batch: function () {
        if (mincointools.wallets.paperwallet.remaining > 0) {
            var paperArea = document.getElementById("paperkeyarea");
            mincointools.wallets.paperwallet.count++;
            var i = mincointools.wallets.paperwallet.count;
            var pageBreakAt = mincointools.wallets.paperwallet.pageBreakAt;
            var div = document.createElement("div");
            div.setAttribute("id", "keyarea" + i);
            if (mincointools.wallets.paperwallet.useArtisticWallet) {
                div.innerHTML = mincointools.wallets.paperwallet.templateArtisticHtml(i);
                div.setAttribute("class", "keyarea art");
            }
            else {
                div.innerHTML = mincointools.wallets.paperwallet.templateHtml(i);
                div.setAttribute("class", "keyarea");
            }
            if (paperArea.innerHTML != "") {
                // page break
                if ((i - 1) % pageBreakAt == 0 && i >= pageBreakAt) {
                    var pBreak = document.createElement("div");
                    pBreak.setAttribute("class", "pagebreak");
                    document.getElementById("paperkeyarea").appendChild(pBreak);
                    div.style.pageBreakBefore = "always";
                    if (!mincointools.wallets.paperwallet.useArtisticWallet) {
                        div.style.borderTop = "2px solid green";
                    }
                }
            }
            document.getElementById("paperkeyarea").appendChild(div);
            mincointools.wallets.paperwallet.generateNewWallet(i);
            mincointools.wallets.paperwallet.remaining--;
            setTimeout(mincointools.wallets.paperwallet.batch, 0);
        }
    },

    // generate bitcoin address, private key, QR Code and update information in the HTML
    // idPostFix: 1, 2, 3, etc.
    generateNewWallet: function (idPostFix) {
        if (mincointools.wallets.paperwallet.encrypt) {
            mincointools.privateKey.BIP38GenerateECAddressAsync(mincointools.wallets.paperwallet.intermediatePoint, false, function (address, encryptedKey) {
                if (mincointools.wallets.paperwallet.useArtisticWallet) {
                    mincointools.wallets.paperwallet.showArtisticWallet(idPostFix, address, encryptedKey);
                }
                else {
                    mincointools.wallets.paperwallet.showWallet(idPostFix, address, encryptedKey);
                }
            });
        }
        else {
            var key = new Bitcoin.ECKey(false);
            var bitcoinAddress = key.getBitcoinAddress();
            var privateKeyWif = key.getBitcoinWalletImportFormat();
            if (mincointools.wallets.paperwallet.useArtisticWallet) {
                mincointools.wallets.paperwallet.showArtisticWallet(idPostFix, bitcoinAddress, privateKeyWif);
            }
            else {
                mincointools.wallets.paperwallet.showWallet(idPostFix, bitcoinAddress, privateKeyWif);
            }
        }
    },

    templateHtml: function (i) {
        var privateKeyLabel = mincointools.translator.get("paperlabelprivatekey");
        if (mincointools.wallets.paperwallet.encrypt) {
            privateKeyLabel = mincointools.translator.get("paperlabelencryptedkey");
        }

        var walletHtml =
            "<div class='public'>" +
                "<div id='qrcode_public" + i + "' class='qrcode_public'></div>" +
                "<div class='pubaddress'>" +
                "<span class='label'>" + mincointools.translator.get("paperlabelbitcoinaddress") + "</span>" +
                "<span class='output' id='btcaddress" + i + "'></span>" +
                "</div>" +
                "</div>" +
                "<div class='private'>" +
                "<div id='qrcode_private" + i + "' class='qrcode_private'></div>" +
                "<div class='privwif'>" +
                "<span class='label'>" + privateKeyLabel + "</span>" +
                "<span class='output' id='btcprivwif" + i + "'></span>" +
                "</div>" +
                "</div>";
        return walletHtml;
    },

    showWallet: function (idPostFix, bitcoinAddress, privateKey) {
        document.getElementById("btcaddress" + idPostFix).innerHTML = bitcoinAddress;
        document.getElementById("btcprivwif" + idPostFix).innerHTML = privateKey;
        var keyValuePair = {};
        keyValuePair["qrcode_public" + idPostFix] = bitcoinAddress;
        keyValuePair["qrcode_private" + idPostFix] = privateKey;
        mincointools.qrCode.showQrCode(keyValuePair);
        document.getElementById("keyarea" + idPostFix).style.display = "block";
    },

    templateArtisticHtml: function (i) {
        var keyelement = 'btcprivwif';
        var image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAewAAAEICAMAAACqITfGAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA2ZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo1NUJDMjI2NkFFQThFMzExOEY5OUVCMzRGRkIyN0Y4MiIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo2MkExRUFFNkE4QjIxMUUzQjdEMkFBNjgwNzg4RUFGQSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo2MkExRUFFNUE4QjIxMUUzQjdEMkFBNjgwNzg4RUFGQSIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M2IChXaW5kb3dzKSI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjU5QkMyMjY2QUVBOEUzMTE4Rjk5RUIzNEZGQjI3RjgyIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjU1QkMyMjY2QUVBOEUzMTE4Rjk5RUIzNEZGQjI3RjgyIi8+IDwvcmRmOkRlc2NyaXB0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';
        if (mincointools.wallets.paperwallet.encrypt) {
            keyelement = 'btcencryptedkey'
        }

        var walletHtml =
            "<div class='artwallet' id='artwallet" + i + "'>" +
                //"<iframe src='bitcoin-wallet-01.svg' id='papersvg" + i + "' class='papersvg' ></iframe>" +
                "<img id='papersvg" + i + "' class='papersvg' src='" + image + "' />" +
                "<div id='qrcode_public" + i + "' class='qrcode_public'></div>" +
                "<div id='qrcode_private" + i + "' class='qrcode_private'></div>" +
                "<div class='btcaddress' id='btcaddress" + i + "'></div>" +
                "<div class='" + keyelement + "' id='" + keyelement + i + "'></div>" +
                "</div>";
        return walletHtml;
    },

    showArtisticWallet: function (idPostFix, bitcoinAddress, privateKey) {
        var keyValuePair = {};
        keyValuePair["qrcode_public" + idPostFix] = bitcoinAddress;
        keyValuePair["qrcode_private" + idPostFix] = privateKey;
        mincointools.qrCode.showQrCode(keyValuePair, 2.5);
        document.getElementById("btcaddress" + idPostFix).innerHTML = bitcoinAddress;

        if (mincointools.wallets.paperwallet.encrypt) {
            var half = privateKey.length / 2;
            document.getElementById("btcencryptedkey" + idPostFix).innerHTML = privateKey.slice(0, half) + '<br />' + privateKey.slice(half);
        }
        else {
            document.getElementById("btcprivwif" + idPostFix).innerHTML = privateKey;
        }

        // CODE to modify SVG DOM elements
        //var paperSvg = document.getElementById("papersvg" + idPostFix);
        //if (paperSvg) {
        //	svgDoc = paperSvg.contentDocument;
        //	if (svgDoc) {
        //		var bitcoinAddressElement = svgDoc.getElementById("bitcoinaddress");
        //		var privateKeyElement = svgDoc.getElementById("privatekey");
        //		if (bitcoinAddressElement && privateKeyElement) {
        //			bitcoinAddressElement.textContent = bitcoinAddress;
        //			privateKeyElement.textContent = privateKeyWif;
        //		}
        //	}
        //}
    },

    toggleArt: function (element) {
        mincointools.wallets.paperwallet.resetLimits();
    },

    toggleEncrypt: function (element) {
        // enable/disable passphrase textbox
        document.getElementById("paperpassphrase").disabled = !element.checked;
        mincointools.wallets.paperwallet.encrypt = element.checked;
        mincointools.wallets.paperwallet.resetLimits();
    },

    resetLimits: function () {
        var hideArt = document.getElementById("paperart");
        var paperEncrypt = document.getElementById("paperencrypt");
        var limit;
        var limitperpage;

        document.getElementById("paperkeyarea").style.fontSize = "100%";
        if (!hideArt.checked) {
            limit = mincointools.wallets.paperwallet.pageBreakAtArtisticDefault;
            limitperpage = mincointools.wallets.paperwallet.pageBreakAtArtisticDefault;
        }
        else if (hideArt.checked && paperEncrypt.checked) {
            limit = mincointools.wallets.paperwallet.pageBreakAtDefault;
            limitperpage = mincointools.wallets.paperwallet.pageBreakAtDefault;
            // reduce font size
            document.getElementById("paperkeyarea").style.fontSize = "95%";
        }
        else if (hideArt.checked && !paperEncrypt.checked) {
            limit = mincointools.wallets.paperwallet.pageBreakAtDefault;
            limitperpage = mincointools.wallets.paperwallet.pageBreakAtDefault;
        }
        document.getElementById("paperlimitperpage").value = limitperpage;
        document.getElementById("paperlimit").value = limit;
    }
};

mincointools.wallets.singlewallet = {
    open: function () {
        if (document.getElementById("btcaddress").innerHTML == "") {
            mincointools.wallets.singlewallet.generateNewAddressAndKey();
        }
        document.getElementById("singlearea").style.display = "block";
    },

    close: function () {
        document.getElementById("singlearea").style.display = "none";
    },

    // generate bitcoin address and private key and update information in the HTML
    generateNewAddressAndKey: function () {
        try {
            var key = new Bitcoin.ECKey(false);
            var bitcoinAddress = key.getBitcoinAddress();
            var privateKeyWif = key.getBitcoinWalletImportFormat();
            document.getElementById("btcaddress").innerHTML = bitcoinAddress;
            document.getElementById("btcprivwif").innerHTML = privateKeyWif;
            var keyValuePair = {
                "qrcode_public": bitcoinAddress,
                "qrcode_private": privateKeyWif
            };
            mincointools.qrCode.showQrCode(keyValuePair, 4);

            document.getElementById("qrcode_public").getElementsByTagName("canvas")[0].className = "single-qr-code";
            document.getElementById("qrcode_private").getElementsByTagName("canvas")[0].className = "single-qr-code";
        }
        catch (e) {
            // browser does not have sufficient JavaScript support to generate a bitcoin address
            alert(e);
            document.getElementById("btcaddress").innerHTML = "error";
            document.getElementById("btcprivwif").innerHTML = "error";
            document.getElementById("qrcode_public").innerHTML = "";
            document.getElementById("qrcode_private").innerHTML = "";
        }
    }
};

mincointools.translator = {
    currentCulture: "en",

    translate: function (culture) {
        var dict = mincointools.translator.translations[culture];
        if (dict) {
            // set current culture
            mincointools.translator.currentCulture = culture;
            // update menu UI
            for (var cult in mincointools.translator.translations) {
                document.getElementById("culture" + cult).setAttribute("class", "");
            }
            document.getElementById("culture" + culture).setAttribute("class", "selected");
            // apply translations
            for (var id in dict) {
                if (document.getElementById(id) && document.getElementById(id).value) {
                    document.getElementById(id).value = dict[id];
                }
                else if (document.getElementById(id)) {
                    document.getElementById(id).innerHTML = dict[id];
                }
            }
        }
    },

    get: function (id) {
        var translation = mincointools.translator.translations[mincointools.translator.currentCulture][id];
        return translation;
    },

    translations: {
        "en": {
            // javascript alerts or messages
            "testneteditionactivated": "TESTNET EDITION ACTIVATED",
            "paperlabelbitcoinaddress": "Mincoin Address:",
            "paperlabelprivatekey": "Private Key (Wallet Import Format):",
            "paperlabelencryptedkey": "Encrypted Private Key (Password required)",
            "bulkgeneratingaddresses": "Generating addresses... ",
            "brainalertpassphrasetooshort": "The passphrase you entered is too short.\n\n",
            "brainalertpassphrasewarning": "Warning: Choosing a strong passphrase is important to avoid brute force attempts to guess your passphrase and steal your coins.",
            "brainalertpassphrasedoesnotmatch": "The passphrase does not match the confirm passphrase.",
            "detailalertnotvalidprivatekey": "The text you entered is not a valid Private Key",
            "detailconfirmsha256": "The text you entered is not a valid Private Key!\n\nWould you like to use the entered text as a passphrase and create a Private Key using a SHA256 hash of the passphrase?\n\nWarning: Choosing a strong passphrase is important to avoid brute force attempts to guess your passphrase and steal your mincoins.",
            "bip38alertincorrectpassphrase": "Incorrect passphrase for this encrypted private key.",
            "bip38alertpassphraserequired": "Passphrase required for BIP38 key",
            "vanityinvalidinputcouldnotcombinekeys": "Invalid input. Could not combine keys.",
            "vanityalertinvalidinputpublickeysmatch": "Invalid input. The Public Key of both entries match. You must input two different keys.",
            "vanityalertinvalidinputcannotmultiple": "Invalid input. Cannot multiply two public keys. Select 'Add' to add two public keys to get a Mincoin address.",
            "vanityprivatekeyonlyavailable": "Only available when combining two private keys",
            "vanityalertinvalidinputprivatekeysmatch": "Invalid input. The Private Key of both entries match. You must input two different keys."
        },

        "es": {
            // javascript alerts or messages
            "testneteditionactivated": "Testnet se activa",
            "paperlabelbitcoinaddress": "Dirección Mincoin:",
            "paperlabelprivatekey": "Clave privada (formato para importar):",
            "paperlabelencryptedkey": "Clave privada cifrada (contraseña necesaria)",
            "bulkgeneratingaddresses": "Generación de direcciones... ",
            "brainalertpassphrasetooshort": "La contraseña introducida es demasiado corta.\n\n",
            "brainalertpassphrasewarning": "Aviso: Es importante escoger una contraseña fuerte para evitar ataques de fuerza bruta a fin de adivinarla y robar tus coins.",
            "brainalertpassphrasedoesnotmatch": "Las contraseñas no coinciden.",
            "detailalertnotvalidprivatekey": "El texto que has introducido no es una clave privada válida",
            "detailconfirmsha256": "El texto que has introducido no es una clave privada válida\n\n¿Quieres usar ese texto como si fuera una contraseña y generar una clave privada usando un hash SHA256 de tal contraseña?\n\nAviso: Es importante escoger una contraseña fuerte para evitar ataques de fuerza bruta a fin de adivinarla y robar tus mincoins.",
            "bip38alertincorrectpassphrase": "Incorrect passphrase for this encrypted private key.", //TODO: please translate
            "bip38alertpassphraserequired": "Passphrase required for BIP38 key", //TODO: please translate
            "vanityinvalidinputcouldnotcombinekeys": "Entrada no válida. No se puede combinar llaves.",
            "vanityalertinvalidinputpublickeysmatch": "Entrada no válida. La clave pública de ambos coincidan entradas. Debe introducir dos claves diferentes.",
            "vanityalertinvalidinputcannotmultiple": "Entrada no válida. No se puede multiplicar dos claves públicas. Seleccione 'Añadir' para agregar dos claves públicas para obtener una dirección Mincoin.",
            "vanityprivatekeyonlyavailable": "Sólo está disponible cuando se combinan dos claves privadas",
            "vanityalertinvalidinputprivatekeysmatch": "Entrada no válida. La clave privada de ambos coincidan entradas. Debe introducir dos claves diferentes.",

            // header and menu html
            "tagline": "Generador de carteras Mincoin de código abierto en lado de cliente con Javascript",
            "generatelabelbitcoinaddress": "Generando dirección Mincoin...",
            "generatelabelmovemouse": "Mueve un poco el ratón para crear entropía...",
            "singlewallet": "Una sola cartera",
            "paperwallet": "Cartera en papel",
            "bulkwallet": "Direcciones en masa",
            "brainwallet": "Cartera mental",
            "vanitywallet": "Cartera personalizada",
            "detailwallet": "Detalles de la cartera",

            // footer html
            "footerlabeldonations": "Donaciones:",
            "footerlabeltranslatedby": "Traducción: <b>12345</b>Vypv2QSmuRXcciT5oEB27mPbWGeva",
            "footerlabelpgp": "PGP",
            "footerlabelversion": "Histórico de versiones",
            "footerlabelgithub": "Repositorio GitHub",
            "footerlabelcopyright1": "Copyright bitaddress.org.",
            "footerlabelcopyright2": "Copyright del código JavaScript: en el fuente.",
            "footerlabelnowarranty": "Sin garantía.",

            // single wallet html
            "newaddress": "Generar dirección",
            "singleprint": "Imprimir",
            "singlelabelbitcoinaddress": "Dirección Mincoin",
            "singlelabelprivatekey": "Clave privada (formato para importar):",
            "singletip1": "<b>A Mincoin wallet</b> is as simple as a single pairing of a Mincoin address with it's corresponding Mincoin private key. Such a wallet has been generated for you in your web browser and is displayed above.", //TODO: please translate
            "singletip2": "<b>To safeguard this wallet</b> you must print or otherwise record the Mincoin address and private key. It is important to make a backup copy of the private key and store it in a safe location. This site does not have knowledge of your private key. If you are familiar with PGP you can download this all-in-one HTML page and check that you have an authentic version from the author of this site by matching the SHA1 hash of this HTML with the SHA1 hash available in the signed version history document linked on the footer of this site. If you leave/refresh the site or press the Generate New Address button then a new private key will be generated and the previously displayed private key will not be retrievable.	Your Mincoin private key should be kept a secret. Whomever you share the private key with has access to spend all the mincoins associated with that address. If you print your wallet then store it in a zip lock bag to keep it safe from water. Treat a paper wallet like cash.", //TODO: please translate
            "singletip3": "<b>Add funds</b> to this wallet by instructing others to send mincoins to your Mincoin address.", //TODO: please translate
            "singletip4": "<b>Check your balance</b> by going to http://mnc.cryptoexplore.com/ and entering your Mincoin address.", //TODO: please translate
            "singletip5": "<b>Spend your mincoins</b> by downloading one of the popular Mincoin p2p clients and importing your private key to the p2p client wallet. Keep in mind when you import your single key to a Mincoin p2p client and spend funds your key will be bundled with other private keys in the p2p client wallet. When you perform a transaction your change will be sent to another Mincoin address within the p2p client wallet. You must then backup the p2p client wallet and keep it safe as your remaining mincoins will be stored there. Satoshi advised that one should never delete a wallet.", //TODO: please translate

            // paper wallet html
            "paperlabelhideart": "Ocultar diseño",
            "paperlabeladdressesperpage": "Direcciones por página:",
            "paperlabeladdressestogenerate": "Direcciones en total:",
            "papergenerate": "Generar",
            "paperprint": "Imprimir",
            "paperlabelBIPpassphrase": "Passphrase:", //TODO: please translate
            "paperlabelencrypt": "BIP38 Encrypt?", //TODO: please translate

            // bulk wallet html
            "bulklabelstartindex": "Empezar en:",
            "bulklabelrowstogenerate": "Filas a generar:",
            "bulklabelcompressed": "Compressed addresses?", //TODO: please translate
            "bulkgenerate": "Generar",
            "bulkprint": "Imprimir",
            "bulklabelcsv": "Valores separados por coma:",
            "bulklabelformat": "Índice,Dirección,Clave privada (formato para importar)",
            "bulklabelq1": "¿Por qué debo usar \"Direcciones en masa\" para aceptar Mincoins en mi web?",
            "bulka1": "La forma tradicional de aceptar mincoins en tu web requiere tener instalado el cliente oficial de Mincoin (\"mincoind\"). Sin embargo muchos servicios de hosting no permiten instalar dicho cliente. Además, ejecutar el cliente en tu servidor supone que las claves privadas están también en el servidor y podrían ser comprometidas en caso de intrusión. Al usar este mecanismo, puedes subir al servidor sólo las dirección de mincoin y no las claves privadas. De esta forma no te tienes que preocupar de que alguien robe la cartera si se cuelan en el servidor.",
            "bulklabelq2": "¿Cómo uso \"Direcciones en masa\" para aceptar mincoins en mi web?",
            "bulklabela2li1": "Usa el tab \"Direcciones en masa\" para generar por anticipado muchas direcciones (más de 10000). Copia y pega la lista de valores separados por comas (CSV) a un archivo de texto seguro (cifrado) en tu ordenador. Guarda una copia de seguridad en algún lugar seguro.",
            "bulklabela2li2": "Importa las direcciones en la base de datos de tu servidor. No subas la cartera ni las claves públicas, o de lo contrario te lo pueden robar. Sube sólo las direcciones, ya que es lo que se va a mostrar a los clientes.",
            "bulklabela2li3": "Ofrece una alternativa en el carro de la compra de tu web para que los clientes paguen con Mincoin. Cuando el cliente elija pagar con Mincoin, les muestras una de las direcciones de la base de datos como su \"dirección de pago\" y guardas esto junto con el pedido.",
            "bulklabela2li4": "Ahora te hace falta recibir una notificación del pago. Busca en google \"notificación de pagos Mincoin\" (o \"mincoin payment notification\" en inglés) y suscríbete a alguno de los servicios que aparezcan. Hay varios de ellos, que te pueden notificar vía Web services, API, SMS, email, etc. Una vez te llegue la notificación, lo cual puede ser automatizado, entonces ya puedes procesar el pedido. Para comprobar a mano si has recibido un pago, puedes usar Block Explorer: reemplaza DIRECCION a continuación por la dirección que estés comprobando. La transacción puede tardar entre 10 minutos y una hora en ser confirmada. <br />http://mnc.cryptoexplore.com/address/DIRECCION<br /><br />Puedes ver las transacciones sin confirmar en: http://mnc.cryptoexplore.com/ <br />Las transacciones sin confirmar suelen aparecer ahí en unos 30 segundos.",
            "bulklabela2li5": "Las mincoins que recibas se almacenarán de forma segura en la cadena de bloques. Usa la cartera original que generaste en el paso 1 para usarlas.",

            // brain wallet html
            "brainlabelenterpassphrase": "Contraseña:",
            "brainlabelshow": "Mostrar",
            "brainprint": "Imprimir",
            "brainlabelconfirm": "Confirmar contraseña:",
            "brainview": "Ver",
            "brainalgorithm": "Algoritmo: SHA256(contraseña)",
            "brainlabelbitcoinaddress": "Dirección Mincoin:",
            "brainlabelprivatekey": "Clave privada (formato para importar):",

            // vanity wallet html
            "vanitylabelstep1": "Paso 1 - Genera tu par de claves",
            "vanitynewkeypair": "Generar",
            "vanitylabelstep1publickey": "Clave pública:",
            "vanitylabelstep1pubnotes": "Copia y pega la línea de arriba en el campo \"Your-Part-Public-Key\" de la web de Vanity Pool.",
            "vanitylabelstep1privatekey": "Clave privada:",
            "vanitylabelstep1privnotes": "Copia y pega la clave pública de arriba en un archivo de texto. Es mejor que lo almacenes en un volumen cifrado. Lo necesitarás para recuperar la clave privada una vez Vanity Pool haya encontrado tu prefijo.",
            "vanitylabelstep2calculateyourvanitywallet": "Paso 2 - Calcula tu cartera personalizada",
            "vanitylabelenteryourpart": "Introduce la clave privada generada en el paso 1, y que has guardado:",
            "vanitylabelenteryourpoolpart": "Introduce la clave privada obtenida de la Vanity Pool:",
            "vanitylabelnote1": "[NOTA: esta casilla de entrada puede aceptar una clave pública o clave privada]",
            "vanitylabelnote2": "[NOTA: esta casilla de entrada puede aceptar una clave pública o clave privada]",
            "vanitylabelradioadd": "Añadir",
            "vanitylabelradiomultiply": "Multiplicar",
            "vanitycalc": "Calcular cartera personalizada",
            "vanitylabelbitcoinaddress": "Dirección Mincoin personalizada:",
            "vanitylabelnotesbitcoinaddress": "Esta es tu nueva dirección, que debería tener el prefijo deseado.",
            "vanitylabelpublickeyhex": "Clave pública personalizada (HEX):",
            "vanitylabelnotespublickeyhex": "Lo anterior es la clave pública en formato hexadecimal.",
            "vanitylabelprivatekey": "Clave privada personalizada (formato para importar):",
            "vanitylabelnotesprivatekey": "Esto es la clave privada para introducir en tu cartera.",

            // detail wallet html
            "detaillabelenterprivatekey": "Introduce la clave privada (en cualquier formato)",
            "detailview": "Ver detalles",
            "detailprint": "Imprimir",
            "detaillabelnote1": "Tu clave privada es un número secreto, único, que sólo tú conoces. Se puede expresar en varios formatos. Aquí abajo mostramos la dirección y la clave pública que se corresponden con tu clave privada, así como la clave privada en los formatos más conocidos (para importar, hex, base64 y mini).",
            "detaillabelnote2": "Mincoin v0.6+ almacena las claves públicas comprimidas. El cliente también soporta importar/exportar claves privadas usando importprivkey/dumpprivkey. El formato de las claves privadas exportadas depende de si la dirección se generó en una cartera antigua o nueva.",
            "detaillabelbitcoinaddress": "Dirección Mincoin:",
            "detaillabelbitcoinaddresscomp": "Dirección Mincoin (comprimida):",
            "detaillabelpublickey": "Clave pública (130 caracteres [0-9A-F]):",
            "detaillabelpublickeycomp": "Clave pública (comprimida, 66 caracteres [0-9A-F]):",
            "detaillabelprivwif": "Clave privada para importar<br />51 caracteres en base58, empieza con un",
            "detaillabelprivwifcomp": "Clave privada para importar<br />comprimida, 52 caracteres en base58, empieza con",
            "detaillabelprivhex": "Clave privada en formato hexadecimal (64 caracteres [0-9A-F]):",
            "detaillabelprivb64": "Clave privada en base64 (44 caracteres):",
            "detaillabelprivmini": "Clave privada en formato mini (22, 26 o 30 caracteres, empieza por 'S'):",
            "detaillabelpassphrase": "BIP38 Passphrase", //TODO: please translate
            "detaildecrypt": "Decrypt BIP38" //TODO: please translate
        },

        "fr": {
            // javascript alerts or messages
            "testneteditionactivated": "ÉDITION TESTNET ACTIVÉE",
            "paperlabelbitcoinaddress": "Adresse Mincoin:",
            "paperlabelprivatekey": "Clé Privée (Format d'importation de porte-monnaie):",
            "paperlabelencryptedkey": "Encrypted Private Key (Password required)", //TODO: please translate
            "bulkgeneratingaddresses": "Création de l'adresse... ",
            "brainalertpassphrasetooshort": "Le mot de passe que vous avez entré est trop court.\n\n",
            "brainalertpassphrasewarning": "Attention: Choisir un mot de passe solide est important pour vous protéger des attaques bruteforce visant à trouver votre mot de passe et voler vos Mincoins.",
            "brainalertpassphrasedoesnotmatch": "Le mot de passe ne correspond pas au mot de passe de vérification.",
            "detailalertnotvalidprivatekey": "Le texte que vous avez entré n'est pas une Clé Privée valide",
            "detailconfirmsha256": "Le texte que vous avez entré n'est pas une Clé Privée valide!\n\nVoulez-vous utiliser le texte comme un mot de passe et créer une Clé Privée à partir d'un hash SHA256 de ce mot de passe?\n\nAttention: Choisir un mot de passe solide est important pour vous protéger des attaques bruteforce visant à trouver votre mot de passe et voler vos Mincoins.",
            "bip38alertincorrectpassphrase": "Incorrect passphrase for this encrypted private key.", //TODO: please translate
            "bip38alertpassphraserequired": "Passphrase required for BIP38 key", //TODO: please translate
            "vanityinvalidinputcouldnotcombinekeys": "Entrée non valide. Impossible de combiner les clés.",
            "vanityalertinvalidinputpublickeysmatch": "Entrée non valide. La clé publique des deux entrées est identique. Vous devez entrer deux clés différentes.",
            "vanityalertinvalidinputcannotmultiple": "Entrée non valide. Il n'est pas possible de multiplier deux clés publiques. Sélectionner 'Ajouter' pour ajouter deux clés publiques pour obtenir une adresse Mincoin.",
            "vanityprivatekeyonlyavailable": "Seulement disponible si vos combinez deux clés privées",
            "vanityalertinvalidinputprivatekeysmatch": "Entrée non valide. La clé Privée des deux entrées est identique. Vous devez entrer deux clés différentes.",

            // header and menu html
            "tagline": "Générateur De Porte-Monnaie Mincoin Javascript Hors-Ligne",
            "generatelabelbitcoinaddress": "Création de l'adresse Mincoin...",
            "generatelabelmovemouse": "BOUGEZ votre souris pour ajouter de l'entropie...",
            "singlewallet": "Porte-Monnaie Simple",
            "paperwallet": "Porte-Monnaie Papier",
            "bulkwallet": "Porte-Monnaie En Vrac",
            "brainwallet": "Porte-Monnaie Cerveau",
            "vanitywallet": "Porte-Monnaie Vanité",
            "detailwallet": "Détails du Porte-Monnaie",

            // footer html
            "footerlabeldonations": "Dons:",
            "footerlabeltranslatedby": "Traduction: 1Gy7NYSJNUYqUdXTBow5d7bCUEJkUFDFSq",
            "footerlabelpgp": "PGP",
            "footerlabelversion": "Historique De Version",
            "footerlabelgithub": "Dépôt GitHub",
            "footerlabelcopyright1": "Copyright bitaddress.org.",
            "footerlabelcopyright2": "Les droits d'auteurs JavaScript sont inclus dans le code source.",
            "footerlabelnowarranty": "Aucune garantie.",

            // single wallet html
            "newaddress": "Générer Une Nouvelle Adresse",
            "singleprint": "Imprimer",
            "singlelabelbitcoinaddress": "Adresse Mincoin:",
            "singlelabelprivatekey": "Clé Privée (Format d'importation de porte-monnaie):",
            "singletip1": "<b>A Mincoin wallet</b> is as simple as a single pairing of a Mincoin address with it's corresponding Mincoin private key. Such a wallet has been generated for you in your web browser and is displayed above.", //TODO: please translate
            "singletip2": "<b>To safeguard this wallet</b> you must print or otherwise record the Mincoin address and private key. It is important to make a backup copy of the private key and store it in a safe location. This site does not have knowledge of your private key. If you are familiar with PGP you can download this all-in-one HTML page and check that you have an authentic version from the author of this site by matching the SHA1 hash of this HTML with the SHA1 hash available in the signed version history document linked on the footer of this site. If you leave/refresh the site or press the Generate New Address button then a new private key will be generated and the previously displayed private key will not be retrievable.	Your Mincoin private key should be kept a secret. Whomever you share the private key with has access to spend all the mincoins associated with that address. If you print your wallet then store it in a zip lock bag to keep it safe from water. Treat a paper wallet like cash.", //TODO: please translate
            "singletip3": "<b>Add funds</b> to this wallet by instructing others to send mincoins to your Mincoin address.", //TODO: please translate
            "singletip4": "<b>Check your balance</b> by going to http://mnc.cryptoexplore.com/ and entering your Mincoin address.", //TODO: please translate
            "singletip5": "<b>Spend your Mincoins</b> by downloading one of the popular mincoins p2p clients and importing your private key to the p2p client wallet. Keep in mind when you import your single key to a Mincoin p2p client and spend funds your key will be bundled with other private keys in the p2p client wallet. When you perform a transaction your change will be sent to another mincoin address within the p2p client wallet. You must then backup the p2p client wallet and keep it safe as your remaining mincoins will be stored there. Satoshi advised that one should never delete a wallet.", //TODO: please translate

            // paper wallet html
            "paperlabelhideart": "Retirer Le Style?",
            "paperlabeladdressesperpage": "Adresses par page:",
            "paperlabeladdressestogenerate": "Nombre d'adresses à créer:",
            "papergenerate": "Générer",
            "paperprint": "Imprimer",
            "paperlabelBIPpassphrase": "Passphrase:", //TODO: please translate
            "paperlabelencrypt": "BIP38 Encrypt?", //TODO: please translate

            // bulk wallet html
            "bulklabelstartindex": "Commencer à l'index:",
            "bulklabelrowstogenerate": "Colonnes à générer:",
            "bulklabelcompressed": "Compressed addresses?", //TODO: please translate
            "bulkgenerate": "Générer",
            "bulkprint": "Imprimer",
            "bulklabelcsv": "Valeurs Séparées Par Des Virgules (CSV):",
            "bulklabelformat": "Index,Adresse,Clé Privée (WIF)",
            "bulklabelq1": "Pourquoi utiliserais-je un Porte-monnaie en vrac pour accepter les Mincoins sur mon site web?",
            "bulka1": "L'approche traditionnelle pour accepter des Mincoins sur votre site web requière l'installation du logiciel Mincoin officiel (\"mincoind\"). Plusieurs hébergeurs ne supportent pas l'installation du logiciel Mincoin. De plus, faire fonctionner le logiciel Mincoin sur votre serveur web signifie que vos clés privées sont hébergées sur le serveur et pourraient donc être volées si votre serveur web était compromis. En utilisant un Porte-monnaie en vrac, vous pouvez publiquer seulement les adresses Mincoin sur votre serveur et non les clés privées. Vous n'avez alors pas à vous inquiéter du risque de vous faire voler votre porte-monnaie si votre serveur était compromis.",
            "bulklabelq2": "Comment utiliser le Porte-monnaie en vrac pour utiliser le Mincoin sur mon site web?",
            "bulklabela2li1": "Utilisez le Porte-monnaie en vrac pour pré-générer une large quantité d'adresses Mincoin (10,000+). Copiez collez les données séparées par des virgules (CSV) dans un fichier texte sécurisé dans votre ordinateur. Sauvegardez ce fichier dans un endroit sécurisé.",
            "bulklabela2li2": "Importez les adresses Mincoin dans une base de donnée sur votre serveur web. (N'ajoutez pas le porte-monnaie ou les clés privées sur votre serveur web, sinon vous courrez le risque de vous faire voler si votre serveur est compromis. Ajoutez seulement les adresses Mincoin qui seront visibles à vos visiteurs.)",
            "bulklabela2li3": "Ajoutez une option dans votre panier en ligne pour que vos clients puissent vous payer en Mincoin. Quand un client choisi de vous payer en Mincoin, vous pouvez afficher une des adresses de votre base de donnée comme \"adresse de paiment\" pour votre client et sauvegarder cette adresse avec sa commande.",
            "bulklabela2li4": "Vous avez maintenant besoin d'être avisé quand le paiement est reçu. Cherchez \"mincoin payment notification\" sur Google et inscrivez-vous à un service de notification de paiement Mincoin. Il y a plusieurs services qui vous avertiront via des services Web, API, SMS, Email, etc. Une fois que vous avez reçu la notification, qui devrait être programmée automatiquement, vous pouvez traiter la commande de votre client. Pour vérifier manuellement si un paiement est arrivé, vous pouvez utiliser Block Explorer. Remplacez ADRESSE par l'adresse Mincoin que vous souhaitez vérifier. La confirmation de la transaction pourrait prendre de 10 à 60 minutes pour être confirmée.<br />http://mnc.cryptoexplore.com/address/ADRESSE<br /><br />Les transactions non confirmées peuvent être visualisées ici: http://mnc.cryptoexplore.com/ <br />Vous devriez voir la transaction à l'intérieur de 30 secondes.",
            "bulklabela2li5": "Les Mincoin vos s'accumuler de façon sécuritaire dans la chaîne de blocs. Utilisez le porte-monnaie original que vous avez généré à l'étape 1 pour les dépenser.",

            // brain wallet html
            "brainlabelenterpassphrase": "Entrez votre mot de passe: ",
            "brainlabelshow": "Afficher?",
            "brainprint": "Imprimer",
            "brainlabelconfirm": "Confirmer le mot de passe: ",
            "brainview": "Visualiser",
            "brainalgorithm": "Algorithme: SHA256(mot de passe)",
            "brainlabelbitcoinaddress": "Adresse Mincoin:",
            "brainlabelprivatekey": "Clé Privée (Format d'importation de porte-monnaie):",

            // vanity wallet html
            "vanitylabelstep1": "Étape 1 - Générer votre \"Étape 1 Paire De Clés\"",
            "vanitynewkeypair": "Générer",
            "vanitylabelstep1publickey": "Étape 1 Clé Publique:",
            "vanitylabelstep1pubnotes": "Copiez celle-ci dans la case Votre-Clé-Publique du site de Vanity Pool.",
            "vanitylabelstep1privatekey": "Step 1 Clé Privée:",
            "vanitylabelstep1privnotes": "Copiez la cette Clé Privée dans un fichier texte. Idéalement, sauvegardez la dans un fichier encrypté. Vous en aurez besoin pour récupérer la Clé Privée lors que Vanity Pool aura trouvé votre préfixe.",
            "vanitylabelstep2calculateyourvanitywallet": "Étape 2 - Calculer votre Porte-monnaie Vanité",
            "vanitylabelenteryourpart": "Entrez votre Clé Privée (générée à l'étape 1 plus haut et précédemment sauvegardée):",
            "vanitylabelenteryourpoolpart": "Entrez la Clé Privée (provenant de Vanity Pool):",
            "vanitylabelnote1": "[NOTE: cette case peut accepter une clé publique ou un clé privée]",
            "vanitylabelnote2": "[NOTE: cette case peut accepter une clé publique ou un clé privée]",
            "vanitylabelradioadd": "Ajouter",
            "vanitylabelradiomultiply": "Multiplier",
            "vanitycalc": "Calculer Le Porte-monnaie Vanité",
            "vanitylabelbitcoinaddress": "Adresse Mincoin Vanité:",
            "vanitylabelnotesbitcoinaddress": "Ci-haut est votre nouvelle adresse qui devrait inclure le préfix requis.",
            "vanitylabelpublickeyhex": "Clé Public Vanité (HEX):",
            "vanitylabelnotespublickeyhex": "Celle-ci est la Clé Publique dans le format hexadécimal. ",
            "vanitylabelprivatekey": "Clé Privée Vanité (WIF):",
            "vanitylabelnotesprivatekey": "Celle-ci est la Clé Privée pour accéder à votre porte-monnaie. ",

            // detail wallet html
            "detaillabelenterprivatekey": "Entrez la Clé Privée (quel que soit son format)",
            "detailview": "Voir les détails",
            "detailprint": "Imprimer",
            "detaillabelnote1": "Votre Clé Privée Mincoin est un nombre secret que vous êtes le seul à connaître. Il peut être encodé sous la forme d'un nombre sous différents formats. Ci-bas, nous affichons l'adresse Mincoin et la Clé Publique qui corresponds à la Clé Privée ainsi que la Clé Privée dans les formats d'encodage les plus populaires (WIF, HEX, B64, MINI).",
            "detaillabelnote2": "Mincoin v0.6+ conserve les clés publiques dans un format compressé. Le logiciel supporte maintenant aussi l'importation et l'exportation de clés privées avec importprivkey/dumpprivkey. Le format de la clé privée exportée est déterminé selon la version du porte-monnaie Mincoin.",
            "detaillabelbitcoinaddress": "Adresse Mincoin:",
            "detaillabelbitcoinaddresscomp": "Adresse Mincoin (compressée):",
            "detaillabelpublickey": "Clé Publique (130 caractères [0-9A-F]):",
            "detaillabelpublickeycomp": "Clé Publique (compressée, 66 caractères [0-9A-F]):",
            "detaillabelprivwif": "Clé Privée WIF<br />51 caractères base58, débute avec un a",
            "detaillabelprivwifcomp": "Clé Privée WIF<br />compressée, 52 caractères base58, débute avec un a",
            "detaillabelprivhex": "Clé Privée Format Hexadecimal (64 caractères [0-9A-F]):",
            "detaillabelprivb64": "Clé Privée Base64 (44 caractères):",
            "detaillabelprivmini": "Clé Privée Format Mini (22, 26 ou 30 caractères, débute avec un 'S'):",
            "detaillabelpassphrase": "BIP38 Passphrase", //TODO: please translate
            "detaildecrypt": "Decrypt BIP38" //TODO: please translate
        },

        "el": {
            // javascript alerts or messages
            "testneteditionactivated": "ΕΝΕΡΓΗ ΕΚΔΟΣΗ TESTNET",
            "paperlabelbitcoinaddress": "Διεύθυνση Mincoin:",
            "paperlabelprivatekey": "Προσωπικό Κλειδί (Μορφή εισαγωγής σε πορτοφόλι):",
            "paperlabelencryptedkey": "Encrypted Private Key (Password required)", //TODO: please translate
            "bulkgeneratingaddresses": "Δημιουργία διευθύνσεων... ",
            "brainalertpassphrasetooshort": "Η φράση κωδικός που δώσατε είναι πολύ αδύναμη.\n\n",
            "brainalertpassphrasewarning": "Προσοχή: Είναι σημαντικό να επιλέξετε μια ισχυρή φράση κωδικό που θα σας προφυλάξει από απόπειρες παραβίασής της τύπου brute force και κλοπή των mincoins σας.",
            "brainalertpassphrasedoesnotmatch": "Η φράση κωδικός και η επιβεβαίωση της δε συμφωνούν.",
            "detailalertnotvalidprivatekey": "Το κείμενο που εισάγατε δεν αντιστοιχεί σε έγκυρο Προσωπικό Κλειδί",
            "detailconfirmsha256": "Το κείμενο που εισάγατε δεν αντιστοιχεί σε έγκυρο Προσωπικό Κλειδί!\n\nΘα θέλατε να χρησιμοποιηθεί το κείμενο ως κωδικός για τη δημιουργία ενός Προσωπικού Κλειδιού που θα δημιουργηθεί από το SHA265 hash της φράσης κωδικού;\n\nΠροσοχή: Είναι σημαντικό να επιλέξετε έναν ισχυρό κωδικό ώστε να είναι δύσκολο να τον μαντέψει κάποιος και να κλέψει τα mincoins σας.",
            "bip38alertincorrectpassphrase": "Λάθος φράση κωδικός αποκρυπτογράφησης Προσωπικού Κλειδιού.",
            "bip38alertpassphraserequired": "Απαιτείται η φράση κωδικός για το Κλειδί BIP38",
            "vanityinvalidinputcouldnotcombinekeys": "Μη έγκυρη εισαγωγή. Ο συνδυασμός των κλειδιών είναι αδύνατος.",
            "vanityalertinvalidinputpublickeysmatch": "Μη έγκυρη εισαγωγή. Τα Δημόσια Κλειδιά των δύο εγγραφών είναι όμοια. Πρέπει να εισάγετε δύο διαφορετικά Κλειδιά.",
            "vanityalertinvalidinputcannotmultiple": "Μη έγκυρη εισαγωγή. Δεν είναι δυνατός ο πολλαπλασιασμός δύο Δημόσιων Κλειδιών. Επιλέξτε 'Πρόσθεση' για να προσθέσετε δύο Δημόσια Κλειδιά για δημιουργία μίας Διεύθυνσης Mincoin.",
            "vanityprivatekeyonlyavailable": "Διαθέσιμο μόνο κατά το συνδυασμό δύο Προσωπικών Κλειδιών",
            "vanityalertinvalidinputprivatekeysmatch": "Μη έγκυρη εισαγωγή. Τα Προσωπικά Κλειδιά των δύο εγγραφών είναι όμοια. Πρέπει να εισάγετε δύο διαφορετικά Κλειδιά.",

            // header and menu html
            "tagline": "Δημιουργός Διευθύνσεων Mincoin, ανοικτού κώδικα Javascript",
            "generatelabelbitcoinaddress": "Δημιουργία Διεύθυνσης Mincoin...",
            "generatelabelmovemouse": "ΚΟΥΝΗΣΤΕ το ποντίκι τριγύρω για να προσθέσετε επιπλέον τυχαιότητα...",
            "singlewallet": "Απλό Πορτοφόλι",
            "paperwallet": "Χάρτινο Πορτοφόλι",
            "bulkwallet": "Πολλαπλά Πορτοφόλια",
            "brainwallet": "Μνημονικό Πορτοφόλι",
            "vanitywallet": "Πορτοφόλι Vanity",
            "detailwallet": "Λεπτομέρειες Πορτοφολιού",

            // footer html
            "footerlabeldonations": "Δωρεές:",
            "footerlabeltranslatedby": "Μετάφραση: <a href='http://LitecoinX.gr/'><b>LitecoinX.gr</b></a> 1BitcoiNxkUPcTFxwMqxhRiPEiQRzYskf6",
            "footerlabelpgp": "PGP",
            "footerlabelversion": "ιστορικό εκδόσεων",
            "footerlabelgithub": "Αποθετήριο GitHub",
            "footerlabelcopyright1": "Copyright bitaddress.org.",
            "footerlabelcopyright2": "Τα πνευματικά δικαιώματα της JavaScript περιλαμβάνονται στον κώδικα.",
            "footerlabelnowarranty": "Καμία εγγύηση.",

            // single wallet html
            "newaddress": "Δημιουργία μιας νέας Διεύθυνσης",
            "singleprint": "Εκτύπωση",
            "singlelabelbitcoinaddress": "Διεύθυνση Mincoin:",
            "singlelabelprivatekey": "Προσωπικό Κλειδί (Μορφή εισαγωγής σε πορτοφόλι):",
            "singletip1": "<b>A Mincoin wallet</b> is as simple as a single pairing of a Mincoin address with it's corresponding Mincoin private key. Such a wallet has been generated for you in your web browser and is displayed above.", //TODO: please translate
            "singletip2": "<b>To safeguard this wallet</b> you must print or otherwise record the Mincoin address and private key. It is important to make a backup copy of the private key and store it in a safe location. This site does not have knowledge of your private key. If you are familiar with PGP you can download this all-in-one HTML page and check that you have an authentic version from the author of this site by matching the SHA1 hash of this HTML with the SHA1 hash available in the signed version history document linked on the footer of this site. If you leave/refresh the site or press the Generate New Address button then a new private key will be generated and the previously displayed private key will not be retrievable.	Your Mincoin private key should be kept a secret. Whomever you share the private key with has access to spend all the mincoins associated with that address. If you print your wallet then store it in a zip lock bag to keep it safe from water. Treat a paper wallet like cash.", //TODO: please translate
            "singletip3": "<b>Add funds</b> to this wallet by instructing others to send mincoins to your Mincoin address.", //TODO: please translate
            "singletip4": "<b>Check your balance</b> by going to http://mnc.cryptoexplore.com/ and entering your Mincoin address.", //TODO: please translate
            "singletip5": "<b>Spend your mincoins</b> by downloading one of the popular mincoins p2p clients and importing your private key to the p2p client wallet. Keep in mind when you import your single key to a mincoin p2p client and spend funds your key will be bundled with other private keys in the p2p client wallet. When you perform a transaction your change will be sent to another Mincoin address within the p2p client wallet. You must then backup the p2p client wallet and keep it safe as your remaining mincoins will be stored there. Satoshi advised that one should never delete a wallet.", //TODO: please translate

            // paper wallet html
            "paperlabelhideart": "Απόκρυψη γραφικού;",
            "paperlabeladdressesperpage": "Διευθύνσεις ανά σελίδα:",
            "paperlabeladdressestogenerate": "Πλήθος διευθύνσεων:",
            "papergenerate": "Δημιουργία",
            "paperprint": "Εκτύπωση",
            "paperlabelBIPpassphrase": "Passphrase:", //TODO: please translate
            "paperlabelencrypt": "BIP38 Encrypt?", //TODO: please translate

            // bulk wallet html
            "bulklabelstartindex": "Ξεκίνημα δείκτη:",
            "bulklabelrowstogenerate": "Πλήθος σειρών:",
            "bulklabelcompressed": "Συμπιεσμένες διευθύνσεις;",
            "bulkgenerate": "Δημιουργία",
            "bulkprint": "Εκτύπωση",
            "bulklabelcsv": "Τιμές που χωρίζονται με κόμμα (CSV):",
            "bulklabelformat": "Δείκτης,Διεύθυνση,Προσωπικό Κλειδί (WIF)",
            "bulklabelq1": "Γιατί να χρησιμοποιήσω Πολλαπλά Πορτοφόλια στην ιστοσελίδα μου;",
            "bulka1": "Ο παραδοσιακός τρόπος για να δέχεστε mincoins στην ιστοσελίδα σας, απαιτεί την εγκατάσταση και λειτουργία του επίσημου δαίμονα πελάτη mincoin (\"mincoind\"). Αρκετά πακέτα φιλοξενίας δεν υποστηρίζουν την εγκατάστασή του. Επιπλέον, η εκτέλεση του πελάτη mincoin στον web server σας συνεπάγεται και τη φιλοξενία των προσωπικών σας κλειδιών στον ίδιο server, τα οποία μπορεί να υποκλαπούν αν ο server πέσει θύμα επίθεσης. Χρησιμοποιώντας τα Πολλαπλά Πορτοφόλια, ανεβάζετε στον server σας μόνο τις διευθύνσεις Mincoin κι όχι τα προσωπικά κλειδιά. Με αυτό τον τρόπο δεν χρειάζεται να ανησυχείτε μήπως υποκλαπεί το πορτοφόλι σας.",
            "bulklabelq2": "Πως χρησιμοποιώ τα Πολλαπλά Πορτοφόλια για να δέχομαι mincoins στην ιστοσελίδα μου;",
            "bulklabela2li1": "Χρησιμοποιήστε την καρτέλα Πολλαπλά Πορτοφόλια για να δημιουργήσετε έναν μεγάλο αριθμό διευθύνσεων Mincoin (10.000+). Αντιγράψτε κι επικολλήστε τη λίστα των χωρισμένων με κόμμα τιμών (CSV) που δημιουργήθηκαν, σε ένα ασφαλές αρχείο στον υπολογιστή σας. Αντιγράψτε το αρχείο που δημιουργήσατε σε μια ασφαλή τοποθεσία.",
            "bulklabela2li2": "Εισάγετε τις διευθύνσεις Mincoin σε έναν πίνακα βάσης δεδομένων στον web server σας. (Μην αντιγράψετε τα προσωπικά κλειδιά ή το πορτοφόλι στον web server γιατί διακινδυνεύετε να σας τα κλέψουν. Μόνο τις διευθύνσεις Mincoin που θα εμφανίζονται στους πελάτες.)",
            "bulklabela2li3": "Παρέχετε στο καλάθι αγορών σας μια επιλογή για πληρωμή σε Mincoin. Όταν ο πελάτης επιλέγει να πληρώσει με Mincoin, θα εμφανίσετε σε αυτόν μια από τις διευθύνσεις από τη βάση δεδομένων, ως την «προσωπική του διεύθυνση πληρωμής» την οποία θα αποθηκεύσετε μαζί με την εντολή αγοράς.",
            "bulklabela2li4": "Τώρα χρειάζεται να ειδοποιηθείτε μόλις γίνει η πληρωμή. Ψάξτε στο Google για «mincoin payment notification» κι εγγραφείτε σε τουλάχιστο μία υπηρεσία ειδοποίησης πληρωμής. Υπάρχουν διάφορες υπηρεσίες που θα σας ειδοποιήσουν με Web υπηρεσίες, API, SMS, Email, κλπ. Όταν λάβετε την ειδοποίηση, η οποία μπορεί να αυτοματοποιηθεί προγραμματιστικά, εκτελείτε την εντολή του πελάτη. Για να ελέγξετε χειροκίνητα την πληρωμή μπορείτε να χρησιμοποιήσετε τον Block Explorer. Αντικαταστήστε το THEADDRESSGOESHERE με τη Mincoin διεύθυνσή σας. Η επιβεβαίωση της πληρωμής ενδέχεται να διαρκέσει από δέκα λεπτά έως μία ώρα.<br />http://mnc.cryptoexplore.com/address/THEADDRESSGOESHERE<br /><br />Μπορείτε να δείτε τις συναλλαγές που δεν έχουν επιβεβαιωθεί στο: http://mnc.cryptoexplore.com/ <br />Θα πρέπει να δείτε τη συναλλαγή εκεί εντός 30 δευτερολέπτων.",
            "bulklabela2li5": "Τα Mincoins θα συσσωρεύονται με ασφάλεια στην αλυσίδα των μπλοκ. Χρησιμοποιήστε το αρχικό πορτοφόλι που δημιουργήσατε στο βήμα 1 για να τα ξοδέψετε.",

            // brain wallet html
            "brainlabelenterpassphrase": "Εισάγετε κωδικό: ",
            "brainlabelshow": "Εμφάνιση;",
            "brainprint": "Εκτύπωση",
            "brainlabelconfirm": "Επιβεβαιώστε τον κωδικό: ",
            "brainview": "Δημιουργία",
            "brainalgorithm": "Αλγόριθμος: SHA256(κωδικός)",
            "brainlabelbitcoinaddress": "Διεύθυνση Mincoin:",
            "brainlabelprivatekey": "Προσωπικό Κλειδί (Μορφή εισαγωγής σε πορτοφόλι):",

            // vanity wallet html
            "vanitylabelstep1": "Βήμα 1 - Δημιουργήστε το «Ζεύγος κλειδιών του Βήματος 1»",
            "vanitynewkeypair": "Δημιουργία",
            "vanitylabelstep1publickey": "Βήμα 1 Δημόσιο Κλειδί:",
            "vanitylabelstep1pubnotes": "Αντιγράψτε κι επικολλήστε το παραπάνω στο πεδίο Your-Part-Public-Key στην ιστοσελίδα του Vanity Pool.",
            "vanitylabelstep1privatekey": "Step 1 Προσωπικό Κλειδί:",
            "vanitylabelstep1privnotes": "Αντιγράψτε κι επικολλήστε το παραπάνω Προσωπικό Κλειδί σε ένα αρχείο κειμένου. Ιδανικά, αποθηκεύστε το σε έναν κρυπτογραφημένο δίσκο. Θα το χρειαστείτε για να ανακτήσετε το Mincoin Προσωπικό Κλειδί όταν βρεθεί το πρόθεμά σας από το Vanity Pool.",
            "vanitylabelstep2calculateyourvanitywallet": "Βήμα 2 - Υπολογίστε το Vanity Πορτοφόλι σας.",
            "vanitylabelenteryourpart": "Εισάγετε το Προσωπικό Κλειδί που δημιουργήσατε στο Βήμα 1 κι αποθηκεύσατε:",
            "vanitylabelenteryourpoolpart": "Εισάγετε το Προσωπικό Κλειδί από το Vanity Pool:",
            "vanitylabelnote1": "[ΣΗΜΕΙΩΣΗ: Το πεδίο αυτό μπορεί να δεχθεί είτε ένα Δημόσιο είτε ένα Προσωπικό Κλειδί.]",
            "vanitylabelnote2": "[ΣΗΜΕΙΩΣΗ: Το πεδίο αυτό μπορεί να δεχθεί είτε ένα Δημόσιο είτε ένα Προσωπικό Κλειδί.]",
            "vanitylabelradioadd": "Πρόσθεσε",
            "vanitylabelradiomultiply": "Πολλαπλασίασε",
            "vanitycalc": "Υπολογισμός του Πορτοφολιού Vanity",
            "vanitylabelbitcoinaddress": "Vanity Διεύθυνση Mincoin:",
            "vanitylabelnotesbitcoinaddress": "Παραπάνω είναι η διεύθυνσή σας που θα πρέπει να περιλαμβάνει το επιθυμητό πρόθεμα.",
            "vanitylabelpublickeyhex": "Vanity Δημόσιο Κλειδί (HEX):",
            "vanitylabelnotespublickeyhex": "Παραπάνω είναι το Δημόσιο Κλειδί σε δεκαεξαδική μορφή. ",
            "vanitylabelprivatekey": "Vanity Προσωπικό Κλειδί (WIF):",
            "vanitylabelnotesprivatekey": "Παραπάνω είναι το Προσωπικό Κλειδί που θα φορτώσετε στο Πορτοφόλι σας. ",

            // detail wallet html
            "detaillabelenterprivatekey": "Εισάγετε το Προσωπικό Κλειδί (οποιαδήποτε μορφή)",
            "detailview": "Προβολή λεπτομερειών",
            "detailprint": "Εκτύπωση",
            "detaillabelnote1": "Το Mincoin Προσωπικό Κλειδί είναι ένας μοναδικός και μυστικός αριθμός που μόνο εσείς πρέπει να γνωρίζετε, ο οποίος μπορεί να κωδικοποιηθεί σε πολλές διαφορετικές μορφές. Εμφανίζουμε παρακάτω τη διεύθυνση Mincoin και το Δημόσιο Κλειδί, μαζί με το Προσωπικό Κλειδί, στις πιο δημοφιλείς μορφές  (WIF, HEX, B64, MINI).",
            "detaillabelnote2": "Το Mincoin v0.6+ αποθηκεύει τα Προσωπικά Κλειδιά σε συμπιεσμένη μορφή. Το πρόγραμμα υποστηρίζει επίσης εισαγωγή κι εξαγωγή των Προσωπικών Κλειδιών με τις εντολές importprivkey/dumpprivkey. Η μορφή του εξαγόμενου Προσωπικού Κλειδιού προσδιορίζεται από το αν η διεύθυνση δημιουργήθηκε σε ένα παλιό ή νέο πορτοφόλι.",
            "detaillabelbitcoinaddress": "Διεύθυνση Mincoin:",
            "detaillabelbitcoinaddresscomp": "Συμπιεσμένη Διεύθυνση Mincoin:",
            "detaillabelpublickey": "Δημόσιο Κλειδί (130 χαρακτήρες [0-9A-F]):",
            "detaillabelpublickeycomp": "Δημόσιο Κλειδί (Συμπιεσμένο, 66 χαρακτήρες [0-9A-F]):",
            "detaillabelprivwif": "Προσωπικό Κλειδί WIF<br />51 χαρακτήρες base58, ξεκινάει με",
            "detaillabelprivwifcomp": "Προσωπικό Κλειδί WIF<br />Συμπιεσμένο, 52 χαρακτήρες base58, ξεκινάει με",
            "detaillabelprivhex": "Προσωπικό Κλειδί Δεκαεξαδική Μορφή (64 χαρακτήρες [0-9A-F]):",
            "detaillabelprivb64": "Προσωπικό Κλειδί Base64 (44 χαρακτήρες):",
            "detaillabelprivmini": "Προσωπικό Κλειδί Μορφή Mini (22, 26 ή 30 χαρακτήρες, ξεκινάει με 'S'):",
            "detaillabelpassphrase": "BIP38 Κωδικός",
            "detaildecrypt": "Αποκωδικοποίηση BIP38"
        }

    }
};

mincointools.translator.showEnglishJson = function () {
    var english = mincointools.translator.translations["en"];
    var spanish = mincointools.translator.translations["es"];
    var spanishClone = {};
    for (var key in spanish) {
        spanishClone[key] = spanish[key];
    }
    var newLang = {};
    for (var key in english) {
        newLang[key] = english[key];
        delete spanishClone[key];
    }
    for (var key in spanishClone) {
        if (document.getElementById(key)) {
            if (document.getElementById(key).value) {
                newLang[key] = document.getElementById(key).value;
            }
            else {
                newLang[key] = document.getElementById(key).innerHTML;
            }
        }
    }
    var div = document.createElement("div");
    div.setAttribute("class", "englishjson");
    div.innerHTML = "<h3>English Json</h3>";
    var elem = document.createElement("textarea");
    elem.setAttribute("rows", "15");
    elem.setAttribute("cols", "110");
    elem.setAttribute("wrap", "off");
    var langJson = "{\n";
    for (var key in newLang) {
        langJson += "\t\"" + key + "\"" + ": " + "\"" + newLang[key].replace(/\"/g, "\\\"").replace(/\n/g, "\\n") + "\",\n";
    }
    langJson = langJson.substr(0, langJson.length - 2);
    langJson += "\n}\n";
    elem.innerHTML = langJson;
    div.appendChild(elem);
    document.body.appendChild(div);
};
