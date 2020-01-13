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
        var image = 'data:image/png;base64,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';
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
