# Recommendations for fixes per rule ID.
# Keep guidance short and actionable.

RULE_FIX_RECOMMENDATIONS = {
    # Parsing
    "JC000": "Fix Java syntax or use supported JavaCard subset; ensure code parses correctly.",

    # Base unsupported features
    "JC001": "Replace float/double with byte/short; use fixed-point (scaled short) for decimals.",
    "JC002": "Remove java.io imports; use APDU buffer for I/O or applet state.",
    "JC003": "Avoid reflection; reference classes directly and instantiate explicitly.",
    "JC004": "Remove System.out/err; handle diagnostics via status words or disable logging.",
    "JC005": "Remove finalize(); JavaCard has no GC finalization.",
    "JC006": "Remove synchronized; JavaCard is single-threaded (no locks needed).",

    # Applet structure and signatures
    "JC007": "Extend javacard.framework.Applet for applet classes.",
    "JC008": "Implement install(byte[] bArray, short bOffset, byte bLength) as public static void.",
    "JC009": "Implement process(APDU apdu) as public void and handle APDU commands.",

    # Security and API usage
    "JC010": "Use ISOException.throwIt(SW) instead of throwing generic Exceptions.",
    "JC011": "Do not store secrets in String; use byte[] and clear as needed.",
    "JC012": "Avoid static byte[] secrets; use JCSystem.makeTransientByteArray or key objects.",
    "JC013": "Remove Thread usage; JavaCard does not support threads.",
    "JC014": "Remove System.gc(); GC control is unavailable on JavaCard.",
    "JC015": "Avoid Arrays.equals for secrets; implement constant-time byte comparison.",

    # APDU and memory practices
    "JC016": "Call apdu.setIncomingAndReceive() before apdu.getBuffer() in process().",
    "JC017": "Use JCSystem.makeTransientByteArray for temporary buffers in process().",
    "JC018": "Call this.register() (or Applet.register) in install().",
    "JC019": "Replace forbidden imports with JavaCard APIs (javacard.security, javacardx.crypto).",
    "JC020": "Remove System.currentTimeMillis/nanoTime; timing APIs are unsupported.",
    "JC021": "Call apdu.setIncomingAndReceive() before apdu.receiveBytes()/getIncomingLength.",
    "JC022": "Add a default in switch to reject unsupported INS/CLA via ISOException.throwIt.",
    "JC023": "Use transient arrays for session buffers; minimize persistent EEPROM byte[].",
    "JC024": "Use javacard.framework.OwnerPIN for PIN management and retries.",
    "JC025": "Do not use java.util.Random; use javacard.security.RandomData.",
    "JC026": "Avoid java.math.BigInteger; use JavaCard crypto APIs for big-number operations.",
    
    # EMV rules
    "JC027": "Implement handlers for GPO (0xA8) and READ RECORD (0xB2) in process() for EMV compliance.",
    "JC028": "Use ISO7816 constants (e.g. ISO7816.SW_NO_ERROR) instead of hardcoded status words.",
}