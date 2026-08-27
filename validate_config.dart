import 'dart:io';
import 'package:xml/xml.dart';

void main() {
  // Read the XML configuration file
  final file = File('config.xml');
  if (!file.existsSync()) {
    print('ERROR: config.xml file not found.');
    exit(1);
  }

  final xmlString = file.readAsStringSync();
  final document = XmlDocument.parse(xmlString);

  print('=== XML Configuration Validation Report ===\n');

  // 1. Validate apiKey is not empty
  final apiKeyElements = document.findAllElements('apiKey');
  if (apiKeyElements.isEmpty) {
    print('[FAIL] apiKey element not found.');
  } else {
    final apiKey = apiKeyElements.first.innerText.trim();
    if (apiKey.isEmpty) {
      print('[FAIL] apiKey is empty.');
    } else {
      print('[WARN] apiKey is present but HARDCODED: \$apiKey');
      print('       -> Security Risk: Sensitive data should not be stored in XML.');
    }
  }

  // 2. Check that timeout is within acceptable range (10-60 seconds)
  final timeoutElements = document.findAllElements('timeout');
  if (timeoutElements.isEmpty) {
    print('[FAIL] timeout element not found.');
  } else {
    final timeoutValue = int.tryParse(timeoutElements.first.innerText.trim());
    if (timeoutValue == null) {
      print('[FAIL] timeout value is not a valid integer.');
    } else if (timeoutValue < 10 || timeoutValue > 60) {
      print('[FAIL] timeout (\$timeoutValue) is out of acceptable range (10-60 seconds).');
    } else {
      print('[PASS] timeout (\$timeoutValue) is within acceptable range.');
    }
  }

  // 3. Verify all user elements have unique id attributes
  final userElements = document.findAllElements('user');
  final idSet = <String>{};
  bool hasDuplicateIds = false;

  for (final user in userElements) {
    final id = user.getAttribute('id');
    if (id == null || id.isEmpty) {
      print('[FAIL] User element missing id attribute.');
      hasDuplicateIds = true;
      continue;
    }
    if (idSet.contains(id)) {
      print('[FAIL] Duplicate user id found: \$id');
      hasDuplicateIds = true;
    } else {
      idSet.add(id);
    }
  }

  if (!hasDuplicateIds && userElements.isNotEmpty) {
    print('[PASS] All user elements have unique id attributes.');
  } else if (userElements.isEmpty) {
    print('[WARN] No user elements found.');
  }

  // 4. Validate firewall rules actions (allow/deny)
  final ruleElements = document.findAllElements('rule');
  bool hasInvalidRule = false;

  for (final rule in ruleElements) {
    final action = rule.getAttribute('action');
    final ip = rule.getAttribute('ip');

    if (action == null) {
      print('[FAIL] Firewall rule missing action attribute.');
      hasInvalidRule = true;
      continue;
    }

    if (action != 'allow' && action != 'deny') {
      print('[FAIL] Invalid firewall rule action: \$action (must be allow or deny)');
      hasInvalidRule = true;
    } else {
      print('[PASS] Valid firewall rule: action=\$action, ip=\$ip');
    }
  }

  if (ruleElements.isEmpty) {
    print('[WARN] No firewall rules found.');
  }

  // Additional Security Checks
  print('\n=== Additional Security Checks ===');

  // Check for hardcoded encryption key
  final keyElements = document.findAllElements('key');
  for (final keyElem in keyElements) {
    final keyText = keyElem.innerText.trim();
    if (keyText.isNotEmpty) {
      print('[WARN] Hardcoded encryption key detected: \$keyText');
      print('       -> Security Risk: Encryption keys should be stored in a secure vault.');
    }
  }

  // Check permissions
  final permissionElements = document.findAllElements('permission');
  for (final perm in permissionElements) {
    final name = perm.getAttribute('name');
    final required = perm.getAttribute('required');
    if (required == 'false') {
      print('[WARN] Permission "$name" is not required. Review if this is intentional.');
    }
  }

  // Check firewall rule order (deny all should be last)
  if (ruleElements.length >= 2) {
    final lastRule = ruleElements.last;
    final lastAction = lastRule.getAttribute('action');
    final lastIp = lastRule.getAttribute('ip');
    if (lastAction == 'deny' && lastIp == '0.0.0.0/0') {
      print('[PASS] Default deny rule (0.0.0.0/0) is correctly placed as the last rule.');
    } else {
      print('[WARN] Default deny rule is NOT the last rule. This may allow unauthorized traffic.');
    }
  }

  print('\n=== Validation Complete ===');
}
