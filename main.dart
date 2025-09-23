import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:network_info_plus/network_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart' as pc;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'WiFi & Nonce Verifier',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const VerifierPage(),
    );
  }
}

class VerifierPage extends StatefulWidget {
  const VerifierPage({super.key});

  @override
  State<VerifierPage> createState() => _VerifierPageState();
}

class _VerifierPageState extends State<VerifierPage> {
  String wifiName = "Unknown";
  String status = "Press button to verify";

  pc.RSAPublicKey? deviceKey;

  final Map<String, dynamic> deviceCert = {
    "device_id": "3311",
    "ssid": "Railway_WiFi",
    "mac": "CC:DB:A7:2F:9C:A1",
    "device_public_key":
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUFizDscAfLH0V+o04UI\nZK+USAXLQ4q6jxnr2l2RCMWn16LQCs/vwa9fbp3ToPTcUzOTiiFlDS6bn9fwsnmU\n6nP+38tFooTqYoydIhfoqUY4gstdu7eVLEzGUDRkk9a+Sz/dVy0Ubk2YEyAEAwgH\nhvBLvyprYyl1BDsX9VqSgaoOnfTc1xHgcZkX4SivHSJntkOoC001IqTOydzn2yqq\nwdPZPbwgDXQdUiLfhE2Utmw+K8sF7x380XQLO1mqsKHF+MdYOK4Lflb7DmNQOJn+\nnFmGN+Ml/BsyFNKp7Y5AonklKD6357huwIDUePcVc7MJ54C5Ulofc6qCl3jrW6PJ\n9wIDAQAB\n-----END PUBLIC KEY-----\n",
  };

  @override
  void initState() {
    super.initState();
    _checkPermissions();
    _loadDeviceKey();
  }

  void _loadDeviceKey() {
    final pubPem = deviceCert['device_public_key']!;
    deviceKey = CryptoUtils.rsaPublicKeyFromPem(pubPem);
  }

  Future<void> _checkPermissions() async {
    var status = await Permission.location.request();
    if (status.isGranted) {
      _getWifiName();
    } else {
      setState(() {
        wifiName = "Permission denied";
      });
    }
  }

  Future<void> _getWifiName() async {
    final info = NetworkInfo();
    String? ssid = await info.getWifiName();
    if (ssid != null) ssid = ssid.replaceAll('"', '').trim();
    setState(() {
      wifiName = ssid ?? "Not connected";
    });
  }

  // ---------------- Single Button Verification ----------------
  Future<void> _verifyWifiAndNonce() async {
    final certSSID = (deviceCert['ssid'] as String).replaceAll('"', '').trim();

    if (wifiName == "Unknown" || wifiName == "Not connected") {
      setState(() {
        status = "❌ Not connected to any WiFi";
      });
      return;
    }

    if (wifiName != certSSID) {
      setState(() {
        status =
            "❌ Connected WiFi ($wifiName) does not match certificate ($certSSID)";
      });
      return;
    }

    setState(() {
      status = "✅ WiFi matches certificate\nFetching nonce...";
    });

    // ---------------- Nonce Verification ----------------
    try {
      final resp = await http
          .get(Uri.parse("http://192.168.4.1/verify"))
          .timeout(const Duration(seconds: 5));

      if (resp.statusCode != 200) {
        setState(() {
          status = "❌ Device returned error: ${resp.statusCode}";
        });
        return;
      }

      final data = json.decode(resp.body);
      final nonce = data['nonce'];
      final signatureHex = data['signature'];

      final sigBytes = Uint8List.fromList(
        List.generate(
          signatureHex.length ~/ 2,
          (i) => int.parse(signatureHex.substring(i * 2, i * 2 + 2), radix: 16),
        ),
      );

      final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201');
      signer.init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(deviceKey!));

      final nonceBytes = utf8.encode(nonce);
      final verified = signer.verifySignature(
        nonceBytes,
        pc.RSASignature(sigBytes),
      );

      setState(() {
        status = verified
            ? "✅ WiFi & Nonce verified!\nNonce: $nonce"
            : "❌ Nonce signature invalid";
      });
    } catch (e) {
      setState(() {
        status = "❌ Failed to reach device: $e";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("WiFi & Nonce Verifier")),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                "Connected WiFi: $wifiName",
                style: const TextStyle(fontSize: 16),
              ),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _getWifiName,
                child: const Text("Refresh WiFi Name"),
              ),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _verifyWifiAndNonce,
                child: const Text("Verify WiFi & Nonce"),
              ),
              const SizedBox(height: 30),
              Text(
                status,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 16),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
