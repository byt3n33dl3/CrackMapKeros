![berberosmd](https://github.com/Sulaimannabdul/KerberossianCracker/assets/151133481/4ad656be-6a95-464f-8d64-6939a210d6b0)

### KerberossianCracker | Kerberos Constrained Delegation


If you have ```compromised a user account``` or a computer (machine account) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user (including administrator) and authenticate to a service that the user account is trusted to delegate to.

## Domain Compromise via DC Print Server and Kerberos Delegation

This lab demonstrates an attack on Active Directory Domain Controller (or any other host to be fair) that involves the following steps and environmental conditions:

* Attacker has to compromise a system that has an unrestricted kerberos delegation enabled.
* Attacker finds a victim that runs a print server. In this lab this happened to be a Domain Controller.
* Attacker coerces the DC to attempt authenticating to the attacker controlled host which has unrestricted kerberos delegation enabled.&#x20;
  * This is done via RPC API  [`RpcRemoteFindFirstPrinterChangeNotificationEx`](https://msdn.microsoft.com/en-us/library/cc244813.aspx) that allows print clients to subscribe to notifications of changes on the print server.
  * Once the API is called, the DC attempts to authenticate to the compromised host by revealing its TGT to the attacker controlled compromised system.
* Attacker extracts `DC01's` TGT from the compromised system and impersonates the DC to carry a DCSync attack and dump domain member hashes.

This lab builds on `Domain Compromise via Unrestricted Kerberos Delegation`
<hr>

#### Execution (referenced from: RTT)

Our environment for this lab is:

* attacker compromised host with kerberos delegation enabled (attacker, server)
* domain controller running a print service (victim, target)

We can check if a spool service is running on a remote host like so:
If the spoolss was not running, we would receive an error.
The above clearly shows the attack was successful and an NTLM hash for the user spotless got retrieved -  get cracking or passing it now.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
KerberosPublicKeyInfo ::= SEQUENCE {
        ap_ticket    [0] EXPLICIT Ticket,
        tgs_ticket   [1] EXPLICIT Ticket OPTIONAL,
        tgs_seskey   [2] EXPLICIT EncryptionKey OPTIONAL
        ...
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#### ***Credit to some UADC and Crackmapexec***
