#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <krb5.h>

#ifndef CKSUMTYPE_SHA1
#define CKSUMTYPE_SHA1 14
#endif


/* OID definitions */

//TODO// decoding to wrong OID values
const uint8_t OID_KEY_TICKET [] = {
	// 1.3.6.1.4.1.44469.666.509.88.1.1.1
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDB, 0x35, 0x85, 0x1A,
	0x83, 0x7D, 0x58, 0x01, 0x01, 0x01, 0x1b
};
#define OID_KEY_TICKET_LEN sizeof (OID_KEY_TICKET)
const uint8_t OID_SIG_AUTHENTICATOR_SHA1 [] = {
	// 1.3.6.1.4.1.44469.666.509.88.1.1.2.1.3.14.3.2.26
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDB, 0x35, 0x85, 0x1A,
	0x83, 0x7D, 0x58, 0x01, 0x01, 0x02,
	0x01, 0x03, 0x0e, 0x03, 0x02, 0x1a
};
#define OID_SIG_AUTHENTICATOR_SHA1_LEN sizeof (OID_SIG_AUTHENTICATOR_SHA1)


/* Find a ticket in the credentials cache
 */
krb5_error_code find_ticket (krb5_context ctx, krb5_ccache cache, char *servicename, krb5_creds **ticket) {
	krb5_error_code kerrno = 0;
	krb5_principal cli;
	int have_cli = 0;
	krb5_principal svc;
	int have_svc = 0;
	krb5_creds match;
	int have_ticket = 0;
	int i;

	//
	// Get the default principal describing the client
	if (!kerrno) {
		kerrno = krb5_cc_get_principal (ctx, cache, &cli);
		have_cli = (kerrno == 0);
	}

	//
	// Possibly build a default principal for the service
	if (!kerrno) {
		if (servicename != NULL) {
			kerrno = krb5_parse_name (ctx, servicename, &svc);
		} else {
			kerrno = krb5_build_principal_ext (ctx, &svc, 
				cli->realm.length, cli->realm.data,
				6, "krbtgt",
				cli->realm.length, cli->realm.data,
				0 /* end marker */ );
		}
		have_svc = (kerrno == 0);
	}

	//
	// Retrieve a ticket for (cli,svc)
	if (!kerrno) {
		memset (&match, 0, sizeof (match));
		match.magic = 0; /*TODO*/
		match.client = cli;
		match.server = svc;
		// kerrno = krb5_cc_retrieve_cred (ctx, cache, 0, &match, ticket);
		kerrno = krb5_get_credentials (ctx, 0, cache, &match, ticket);
		have_ticket = (kerrno == 0);
	}
	if (!kerrno) {
		//TODO// kerrno = krb5int_validate_times (ctx, (*ticket)->times);
		//TODO// use KRB5_TC_MATCH_TIMES to enforce match's lifetimes
	}

	//
	// Print ticket descriptive information
	if (have_cli) {
		printf ("-----BEGIN CLIENT PRINCIPAL-----\n");
		printf ("NameType: %d\n", cli->type);
		for (i=0; i<cli->length; i++) {
			printf ("Name_%d: %.*s\n", i, cli->data [i].length, cli->data [i].data);
		}
		printf ("Realm: %.*s\n", svc->realm.length, svc->realm.data);
		printf ("-----END CLIENT PRINCIPAL-----\n");
	}
	printf ("\n");
	if (have_svc) {
		printf ("-----BEGIN SERVICE PRINCIPAL-----\n");
		printf ("NameType: %d\n", svc->type);
		for (i=0; i<svc->length; i++) {
			printf ("Name_%d: %.*s\n", i, svc->data [i].length, svc->data [i].data);
		}
		printf ("Realm: %.*s\n", svc->realm.length, svc->realm.data);
		printf ("-----END SERVICE PRINCIPAL-----\n");
	}
	printf ("\n");
	if (have_ticket) {
		printf ("-----BEGIN TICKET HEXDUMP-----\n");
		i = 0;
		while (i < (*ticket)->ticket.length) {
			char sep = (((i & 15) != 15) && (i != (*ticket)->ticket.length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) (*ticket)->ticket.data [i++], sep);
		}
		printf ("-----END TICKET HEXDUMP-----\n");
	}

	//
	// Cleanup
	if (kerrno && have_ticket) {
		krb5_free_cred_contents (ctx, *ticket);
		*ticket = NULL;
		have_ticket = 0;
	}
	if (have_svc) {
		krb5_free_principal (ctx, svc);
		have_svc = 0;
	}
	if (have_cli) {
		krb5_free_principal (ctx, cli);
		have_cli = 0;
	}

	//
	// Return the overall result
	return kerrno;
}


/* Construct an Authenticator object with the given checksum
 */
krb5_error_code construct_enc_authenticator (krb5_context ctx, krb5_creds *ticket, krb5_checksum *csum_opt, krb5_enc_data *enc_authenticator) {
	krb5_error_code kerrno = 0;
	krb5_authenticator auth;
	krb5_data *plain_asn1 = NULL;
	krb5_enc_data *enc_asn1 = NULL;
	int i;

	//
	// Fill the authenticator fields
	memset (&auth, 0, sizeof (auth));
	auth.magic = 0; /*TODO*/
	auth.client = ticket->client;
	if (csum_opt) {
		auth.checksum = csum_opt;
	}
	if (!kerrno) {
		kerrno = krb5_us_timeofday (ctx, &auth.ctime, &auth.cusec);
	}

	//
	// Represent the authenticator in ASN.1 / DER
	if (!kerrno) {
		plain_asn1 = malloc (sizeof (*plain_asn1));
		if (plain_asn1 == NULL) {
			perror ("Allocating plaintext authenticator");
			//TODO// Setup as kerrno
			exit (1);
		}
	}
	if (!kerrno) {
		memset (plain_asn1, 0, sizeof (plain_asn1));
		plain_asn1->magic = 0; /*TODO*/
		kerrno = encode_krb5_authenticator (&auth, &plain_asn1);
	}

	//
	// Encrypt the authenticator
	//TODO// Build up to EncryptedData?
	if (!kerrno) {
		enc_asn1 = malloc (sizeof (*enc_asn1));
		if (enc_asn1 == NULL) {
			perror ("Allocating encrypted authenticator");
			//TODO// Setup as kerrno value
			exit (1);
		}
	}
	if (!kerrno) {
		size_t enclen = 0;
		enc_asn1->magic = 0; /*TODO*/
		kerrno = krb5_c_encrypt_length (ctx, ticket->keyblock.enctype, plain_asn1->length, &enclen);
		enc_asn1->ciphertext.length = enclen;
		if (!kerrno) {
			enc_asn1->ciphertext.data = malloc (enc_asn1->ciphertext.length);
			if (!enc_asn1->ciphertext.data) {
				perror ("Allocating encrypted authenticator block");
				//TODO// Setup as kerrno value
				exit (1);
			}
		}
	}
	if (!kerrno) {
		kerrno = krb5_c_encrypt (ctx, &ticket->keyblock, KRB5_KEYUSAGE_AP_REQ_AUTH /*TODO:STOLEN11:OR10ADDS:_CKSUM*/, NULL, plain_asn1, enc_asn1);
	}

	//
	// Print representations
	printf ("\n");
	if (plain_asn1) {
		printf ("-----BEGIN AUTHENTICATOR HEXDUMP-----\n");
		i = 0;
		while (i < plain_asn1->length) {
			char sep = (((i & 15) != 15) && (i != plain_asn1->length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) plain_asn1->data [i++], sep);
		}
		printf ("-----END AUTHENTICATOR HEXDUMP-----\n");
	}
	printf ("\n");
	if (enc_asn1) {
		printf ("-----BEGIN ENCAUTHENTICATOR HEXDUMP-----\n");
		i = 0;
		while (i < enc_asn1->ciphertext.length) {
			char sep = (((i & 15) != 15) && (i != enc_asn1->ciphertext.length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) enc_asn1->ciphertext.data [i++], sep);
		}
		printf ("-----END ENCAUTHENTICATOR HEXDUMP-----\n");
	}


	//
	// Cleanup
	if (plain_asn1->data) {
		free (plain_asn1->data);
		plain_asn1->length  = 0;
	}
	if (kerrno && enc_asn1 && enc_asn1->ciphertext.data) {
		free (enc_asn1->ciphertext.data);
		enc_asn1->ciphertext.data = NULL;
		enc_asn1->ciphertext.length = 0;
	}
	if (kerrno && enc_asn1) {
		free (enc_asn1);
		enc_asn1 = NULL;
	}

	//
	// Return the overall result
	if (!kerrno) {
		*enc_authenticator = *enc_asn1;
		free (enc_asn1);
	}
	return kerrno;
}

asn1_error_code encode_x509 (krb5_context ctx, struct timeval *timestamp_opt, krb5_creds *ticket, krb5_data **x509) {
	asn1_error_code aerrno = 0;
	asn1buf *tbsbuf;
	int have_tbsbuf = 0;
	krb5_data *tbscert;
	int have_tbscert = 0;
	asn1buf *x509buf;
	int have_x509buf = 0;
	unsigned int certlen = 0, tbslen = 0, sublen, seqlen, seq2len;
	time_t sigtime;
	int i;
	krb5_data *encauthbits;
	int have_encauthbits = 0;
	uint8_t *tbshash = NULL;
	int have_tbshash = 0;
	krb5_enc_data enc_authenticator;
	int have_enc_authenticator = 0;
	krb5_checksum checksum;

	//
	// Initialise working context
	if (!aerrno) {
		aerrno = asn1buf_create (&x509buf);
		have_x509buf = (aerrno == 0);
	}
	if (!aerrno) {
		aerrno = asn1buf_create (&tbsbuf);
		have_tbsbuf = (aerrno == 0);
	}
	if (timestamp_opt) {
		sigtime = timestamp_opt->tv_usec;
	} else {
		if (time (&sigtime) == (time_t) -1) {
			perror ("Failed to read the time");
			//TODO// Setup as aerrno
			exit (1);
		}
	}

	//
	// Fill out the TBSCertificate structure [RFC3280]:
	//
	// TBSCertificate  ::=  SEQUENCE  {
	//	version         [0]  EXPLICIT Version DEFAULT v1,
	//	serialNumber         CertificateSerialNumber,
	//	signature            AlgorithmIdentifier,
	//	issuer               Name,
	//	validity             Validity,
	//	subject              Name,
	//	subjectPublicKeyInfo SubjectPublicKeyInfo,
	//	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//	                     -- If present, version MUST be v2 or v3
	//	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//	                     -- If present, version MUST be v2 or v3
	//	extensions      [3]  EXPLICIT Extensions OPTIONAL
	//	                     -- If present, version MUST be v3
	// }
	//
	// The buildup is in reverse order!
	// SKIP extensions
	// SKIP subjectUniqueID
	// SKIP issuerUniqueID
	if (!aerrno) {
		// subjectPublicKeyInfo_pre2 <-- BITSTRING (ticket)
		aerrno = asn1_encode_bitstring (tbsbuf, ticket->ticket.length, ticket->ticket.data, &sublen);
		seqlen = sublen;
	}
	if (!aerrno) {
		// subjectPublicKeyInfo_pre12 (parameters) absent, not used here
		// subjectPublicKeyInfo_pre11 <-- OID for Kerberos Ticket
		aerrno = asn1_encode_oid (tbsbuf, OID_KEY_TICKET_LEN, OID_KEY_TICKET, &sublen);
		seq2len = sublen;
	}
	if (!aerrno) {
		// subjectPublicKeyInfo_pre1 <-- AlgorithmIdentifier {_pre11,_pre12}
		aerrno = asn1_make_sequence (tbsbuf, seq2len, &sublen);
		seqlen += seq2len + sublen;
	}
	if (!aerrno) {
		// subjectPublicKeyInfo <-- SEQUENCE {_pre1, _pre2}
		aerrno = asn1_make_sequence (tbsbuf, seqlen, &sublen);
		tbslen += seqlen + sublen;
	}
	if (!aerrno) {
		// subject <-- CHOICE (RDNSequence (empty))
		aerrno = asn1_make_sequence (tbsbuf, 0, &sublen);
		tbslen += 0 + sublen;
	}
	if (!aerrno) {
		// validity_pre2 <-- CHOICE (GeneralTime (now + 3 min))
		aerrno = asn1_encode_generaltime (tbsbuf, sigtime + 180, &sublen);
		seqlen = sublen;
	}
	if (!aerrno) {
		// validity_pre1 <-- CHOICE (GeneralTime (now - 2 min))
		aerrno = asn1_encode_generaltime (tbsbuf, sigtime - 120, &sublen);
		seqlen += sublen;
	}
	if (!aerrno) {
		// validity <-- SEQUENCE {validity_pre1, validity_pre2}
		aerrno = asn1_make_sequence (tbsbuf, seqlen, &sublen);
		tbslen += seqlen + sublen;
	}
	if (!aerrno) {
		// issuer <-- CHOICE (RDNSequence (empty))
		aerrno = asn1_make_sequence (tbsbuf, 0, &sublen);
		tbslen += 0 + sublen;
	}
	if (!aerrno) {
		// signature_pre2 (parameters) absent, not used here
		// signature_pre1 <-- OID for Kerberos signing
		aerrno = asn1_encode_oid (tbsbuf, OID_SIG_AUTHENTICATOR_SHA1_LEN, OID_SIG_AUTHENTICATOR_SHA1, &sublen);
		seqlen = sublen;
	}
	if (!aerrno) {
		// signature <-- AlgorithmIdentifier {signature_pre1, signature_pre2}
		aerrno = asn1_make_sequence (tbsbuf, seqlen, &sublen);
		tbslen += seqlen + sublen;
	}
	if (!aerrno) {
		// serialNumber <-- INTEGER timestamp (or 0)
		asn1_intmax ts;
		if (timestamp_opt) {
			//TODO// Subtract ticket signtime start
			ts = 1000000 * timestamp_opt->tv_sec
			             + timestamp_opt->tv_usec;
			if (ts / 1000000 < timestamp_opt->tv_sec) {
				fprintf (stderr, "Warning: Timestamp range clipped\n");
			}
		} else {
			ts = 0;
		}
		aerrno = asn1_encode_integer (tbsbuf, ts, &sublen);
		tbslen += sublen;
	}
	if (!aerrno) {
		// version_pre <-- INTEGER { v3(2) }
		aerrno = asn1_encode_integer (tbsbuf, 2, &sublen);
		seqlen = sublen;
	}
	if (!aerrno) {
		// version <-- [0] EXPLICIT version_pre
		aerrno = asn1_make_tag (tbsbuf, CONTEXT_SPECIFIC, CONSTRUCTED, 0 /*tagnum*/, seqlen, &sublen);
		tbslen += seqlen + sublen;
	}

	//
	// SEQUENCE all the TBSCertificate components together
	if (!aerrno) {
		// TBSCertificate <-- SEQUENCE {all_of_the_above}
		aerrno = asn1_make_sequence (tbsbuf, tbslen, &sublen);
		//TODO// Length seems to be off
		tbslen += sublen;
	}

	//
	// Now form a temporary data buffer for the TBSCertificate
	if (!aerrno) {
		aerrno = asn12krb5_buf (tbsbuf, &tbscert);
		have_tbscert = (aerrno == 0);
	}

	//
	// Now hash the TBSCertificate and fill the krb5_checksum
	if (!aerrno) {
		int ok = 1;
		SHA_CTX hctx;
		tbshash = malloc (20);
		ok = ok && (tbshash != NULL);
		ok = ok && SHA1_Init (&hctx);
		ok = ok && SHA1_Update (&hctx, tbscert->data, tbscert->length);
		ok = ok && SHA1_Final (tbshash, &hctx);
		if (!ok) {
			if (tbshash != NULL) {
				free (tbshash);
				aerrno = ENOMEM;  //TODO// Better one?
			} else {
				aerrno = ENOMEM;
			}
		}
		have_tbshash = (ok == 1);
	}
	if (!aerrno) {
		memset (&checksum, 0, sizeof (checksum));
		checksum.magic = 0;	//TODO// Better value
		checksum.checksum_type = CKSUMTYPE_SHA1;
		checksum.length = 20;
		checksum.contents = tbshash;
	}

	//
	// Construct an authenticator for the ticket
	if (!aerrno) {
		aerrno = construct_enc_authenticator (ctx, ticket, &checksum, &enc_authenticator);
		//TODO// Really krb5_error_code
		have_enc_authenticator = (aerrno == 0);
	}

	//
	// Construct the Certificate [RFC3280]:
	//
	// Certificate  ::=  SEQUENCE  {
	//	tbsCertificate       TBSCertificate,
	//	signatureAlgorithm   AlgorithmIdentifier,
	//	signatureValue       BIT STRING
	// }
	//
	// Buildup is in reverse order!
	if (!aerrno) {
		assert (have_enc_authenticator);
		// authenticator_pre1 <-- EncryptedData {Authenticator}
		//TODO// Function really returns a krb5_error_code
		aerrno = encode_krb5_enc_data (&enc_authenticator, &encauthbits);
		//TODO// Possible problem: optional kvno field not included
		have_encauthbits = (aerrno == 0);
	}
	if (!aerrno) {
		// authenticator_pre1 <-- 0:authenticator_pre11
		assert (have_encauthbits);
		aerrno = asn1_encode_bitstring (x509buf, encauthbits->length, encauthbits->data, &sublen);
		certlen += sublen;
	}
	if (!aerrno) {
		// signatureAlgorithm_pre1 <-- OID for Kerberos Signing
		// signatureAlgorithm_pre2 (parameters) absent, not used here
		aerrno = asn1_encode_oid (x509buf, OID_SIG_AUTHENTICATOR_SHA1_LEN, OID_SIG_AUTHENTICATOR_SHA1, &sublen);
		seqlen = sublen;
	}
	if (!aerrno) {
		// signatureAlgorithm <-- SEQUENCE {_pre1,_pre2}
		aerrno = asn1_make_sequence (x509buf, seqlen, &sublen);
		certlen += seqlen + sublen;
	}
	if (!aerrno) {
		// tbsCertificate <-- Prepared tbscert buffer
		assert (have_tbscert);
		aerrno = asn1buf_insert_bytestring (x509buf, tbscert->length, tbscert->data);
		certlen += tbscert->length;
	}

	//
	// Pull all the Certificate parts together
	if (!aerrno) {
		// Certificate <-- SEQUENCE {all_of_the_above}
		aerrno = asn1_make_sequence (x509buf, certlen, &sublen);
		//TODO// Length seems to be off
		certlen += sublen;
	}

	//
	// Export the ASN.1 buffer data to a krb5_data structure
	if (!aerrno) {
		aerrno = asn12krb5_buf (x509buf, x509);
		if (aerrno) {
			krb5_free_data (ctx, *x509);
		}
	}

	//
	// Print the result for debugging
	printf ("\n");
	if (!aerrno) {
		printf ("-----BEGIN TO-BE-SIGNED-CERTIFICATE HEXDUMP-----\n");
		i = 0;
		while (i < tbscert->length) {
			char sep = (((i & 15) != 15) && (i != tbscert->length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) tbscert->data [i++], sep);
		}
		printf ("-----END TO-BE-SIGNED-CERTIFICATE HEXDUMP-----\n");
	}
	printf ("\n");
	if (tbshash != NULL) {
		printf ("SHA1(tbscert) =");
		for (i=0; i<20; i++) {
			printf (" %02x", tbshash [i]);
		}
		printf ("\n");
	}
	printf ("\n");
	if (!aerrno) {
		printf ("-----BEGIN CERTIFICATE HEXDUMP-----\n");
		i = 0;
		while (i < (*x509)->length) {
			char sep = (((i & 15) != 15) && (i != (*x509)->length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) (*x509)->data [i++], sep);
		}
		printf ("-----END CERTIFICATE HEXDUMP-----\n");
	}

	//
	// Cleanup
	if (have_enc_authenticator) {
		free (enc_authenticator.ciphertext.data);
		have_enc_authenticator = 0;
	}
	if (have_encauthbits) {
		krb5_free_data (ctx, encauthbits);
		have_encauthbits = 0;
	}
	if (have_tbshash) {
		free (tbshash);
		have_tbshash = 0;
	}
	if (have_tbscert) {
		krb5_free_data (ctx, tbscert);
		have_tbscert = 0;
	}
	if (have_tbsbuf) {
		asn1buf_destroy (&tbsbuf);
		have_tbsbuf = 0;
	}
	if (have_x509buf) {
		asn1buf_destroy (&x509buf);
		have_x509buf = 0;
	}

	//
	// Return the success or failure value
	return aerrno;
}


/* Main routine
 */
int main (int argc, char *argv []) {
	krb5_error_code kerrno = 0;
	krb5_context ctx;
	int have_ctx = 0;
	krb5_ccache cache;
	int have_cache = 0;
	krb5_creds *ticket;
	int have_ticket = 0;
	krb5_data *x509;
	int have_x509 = 0;
	char *servicename = NULL;

	//
	// Parse commandline
	if (argc > 2) {
		fprintf (stderr, "Usage: %s [servicename]\n", argv [0]);
		exit (1);
	} else if (argc == 2) {
		servicename = argv [1];
	}

	//
	// Allocate and Initialise resources
	if (!kerrno) {
		kerrno = krb5_init_context (&ctx);
		have_ctx = (kerrno == 0);
	}
	if (!kerrno) {
		kerrno = krb5_cc_default (ctx, &cache);
		have_cache = (kerrno == 0);
	}

	//
	// Obtain a ticket
	if (!kerrno) {
		kerrno = find_ticket (ctx, cache, servicename, &ticket);
		have_ticket = (kerrno == 0);
	}

	//
	// Using the ticket and authenticator, build an X.509 certificate
	if (!kerrno) {
		//TODO// kerrno is actually asn1_error_code aerrno
		kerrno = encode_x509 (ctx, NULL, ticket, &x509);
		have_x509 = (kerrno != 0);
	}

	//
	// Error reporting and Cleanup
	if (kerrno) {
		const char *errmsg = krb5_get_error_message (ctx, kerrno);
		fprintf (stderr, "Error in Kerberos: %s\n", errmsg);
		krb5_free_error_message (ctx, errmsg);
	}
	if (have_x509) {
		krb5_free_data (ctx, x509);
		have_x509 = 0;
	}
	if (have_ticket) {
		krb5_free_creds (ctx, ticket);
		have_ticket = 0;
	}
	if (have_cache) {
		krb5_cc_close (ctx, cache);
		have_cache = 0;
	}
	if (have_ctx) {
		krb5_free_context (ctx);
		have_ctx = 0;
	}

	exit (kerrno);
}
