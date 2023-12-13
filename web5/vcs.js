import { VerifiableCredential, PresentationExchange } from "@web5/credentials";
import { DidKeyMethod } from "@web5/dids";
import { Web5 } from "@web5/api";
import { Ed25519, Jose } from "@web5/crypto";

// Create a DID key for the issuer and subject
const vcIssuerDid = await DidKeyMethod.create();
const vcHolderDid = await DidKeyMethod.create();

// Create a verifiable credential
class TswiftTicket {
  constructor(seat, date) {
    this.seat = seat;
    this.date = date;
  }
}

//Credential needs: type, issuer, subject, and data
const vc = VerifiableCredential.create({
  type: "TswiftTicket",
  issuer: vcIssuerDid.did,
  subject: vcHolderDid.did,
  data: new TswiftTicket("A-1", "2025-11-11"),
});

// Signing a credential
const privateKey = vcIssuerDid.keySet.verificationMethodKeys[0].privateKeyJwk;

const signOptions = {
  issuerDid: vcIssuerDid.did,
  subjectDid: vcHolderDid.did,
  kid: `${vcHolderDid.did}#${vcHolderDid.did.split(":")[2]}`,
  signer: async (data) => await Ed25519.sign({ data, key: privateKey }),
};

const signedVc = await vc.sign(signOptions);

try {
  await VerifiableCredential.verify(signedVc);
  console.log("Verification succcessful!\n");
} catch (err) {
  console.log("\nVC Verification failed: " + err.message + "\n");
}

const parsedVc = VerifiableCredential.parseJwt(signedVc);
//console.log("Parsed VC: \n" + parsedVc + '\n');

/** Presentation Exchange */

// Create Presentation Definition
const presentationDefinition = {
  id: "presDefId123",
  name: "T Swift Ticket Presentation Definition",
  purpose: "for getting into the concert",
  input_descriptors: [
    {
      id: "seat",
      purpose: "where are you going to sit",
      constraints: {
        fields: [
          {
            path: ["$.credentialSubject.seat"],
          },
        ],
      },
    },
  ],
};

// Satisfies Presentation Definition
try {
  PresentationExchange.validateDefinition(presentationDefinition);
  PresentationExchange.satisfiesPresentationDefinition(
    [signedVc],
    presentationDefinition
  );
  console.log("\nVC Satisfies Presentation Definition!\n");
} catch (err) {
  console.log("VC does not satisfy Presentation Definition: " + err.message);
}
