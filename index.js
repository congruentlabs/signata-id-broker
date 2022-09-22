const express = require("express");
const ethers = require("ethers");
const crypto = require("crypto");
const axios = require("axios");
const { createHmac } = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { Web3Storage, File } = require("web3.storage");
const Name = require("w3name");

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const signingAuthority = process.env.SIGNING_KEY;
const TXTYPE_CLAIM_DIGEST = process.env.TXTYPE_CLAIM_DIGEST;
const DOMAIN_SEPARATOR = process.env.DOMAIN_SEPARATOR;
const BLOCKPASS_SECRET = process.env.BLOCKPASS_SECRET;
const CHAINALYSIS_SECRET = process.env.CHAINALYSIS_SECRET;

const supabase = createClient(supabaseUrl, supabaseKey);

const client = new Web3Storage({ token: process.env.WEB3STORAGE_TOKEN });

app.get("/", (req, res) => {
  res.send({ service: "signata-id-broker", version: "0.0.2" });
});

/**
 * Request a KYC claim signature. Verifies that the user has completed KYC with Blockpass.
 * Later this will be extended to support other KYC providers.
 */
app.get("/api/v1/requestKyc/:id", async (req, res) => {
  const { data, error } = await supabase
    .from("blockpass_events")
    .select("*")
    .eq("refId", req.params.id);

  if (error) {
    console.error(error);
    return res.status(500).json({ error: "Events Error" });
  }
  if (data.length === 0) {
    return res.status(204).json({ message: "No data found" });
  }

  // check it's not a sanctioned address
  const sanctionResponse = await axios.get('https://public.chainalysis.com/api/v1/address/' + req.params.id, { headers: {
    'X-API-KEY': CHAINALYSIS_SECRET, 'Accept': 'application/json'
  }})

  if (sanctionResponse !== 200) {
    return res.status(500).json({ error: "Sanction lookup failed" });
  }

  if (sanctionResponse.data && sanctionResponse.data  ) {
    // TODO: read the sanction data and check if it's a sanctioned address
    return res.status(403).json({ error: "Address is sanctioned" });
  }

  // find an existing signature
  const { data: existingRecord, error: existingRecordError } = await supabase
    .from("kyc_claims")
    .select("sigR, sigS, sigV, salt")
    .eq("identity", req.params.id);

  if (existingRecordError) {
    console.error(existingRecordError);
    return res.status(500).json({ error: "Existing Record Error" });
  }

  if (existingRecord.length > 0) {
    // return the existing signature
    console.log("found existing record");
    return res.status(200).json({
      sigR: existingRecord[0].sigR,
      sigS: existingRecord[0].sigS,
      sigV: existingRecord[0].sigV,
      salt: existingRecord[0].salt,
    });
  }

  console.log("no existing record, creating new one");
  // salt doesn't need to be ultra random. It's more about restricting the reuse of claims.
  const salt = crypto.randomBytes(32).toString("hex");
  const inputHash = ethers.utils.keccak256(
    `${TXTYPE_CLAIM_DIGEST}${req.params.id
      .slice(2)
      .padStart(64, "0")}${salt.padStart(64, "0")}`
  );
  const hashToSign = ethers.utils.keccak256(
    `0x1901${DOMAIN_SEPARATOR.slice(2)}${inputHash.slice(2)}`
  );
  const signature = new ethers.utils.SigningKey(signingAuthority).signDigest(
    hashToSign
  );
  console.log({
    salt,
    inputHash,
    hashToSign,
    signature,
  });

  const { error: insertError } = await supabase.from("kyc_claims").insert({
    identity: req.params.id,
    sigR: signature.r,
    sigS: signature.s,
    sigV: signature.v,
    salt,
  });

  if (insertError) {
    console.error(insertError);
    return res.status(500).json({ error: "Insert Error" });
  }

  return res.status(200).json({
    sigR: signature.r,
    sigS: signature.s,
    sigV: signature.v,
    salt,
  });
});

/**
 * Process webhooks generated by blockpass.
 * X-Hub-Signature is used to verify the authenticity of the request.
 */
app.post("/api/v1/blockpassWebhook", async (req, res) => {
  const data = req.body;

  if (!data) {
    return res.status(400).json({ error: "No Data" });
  }
  console.log(data);

  const requestSignature = req.get("X-Hub-Signature");
  const algo = "sha256";
  const hmac = createHmac(algo, BLOCKPASS_SECRET);
  hmac.update(JSON.stringify(data));
  const result = hmac.digest("hex");

  if (result !== requestSignature) {
    console.log({
      message: "signature verification failed",
      requestSignature,
      result,
    });
    return res.status(403).json({ error: "Invalid Signature" });
  }

  const { error } = await supabase.from("blockpass_events").insert(data);
  if (error) {
    console.error(error);
    return res.status(500).json({ error: "Events Error" });
  }
  return res.status(200).json({ message: "Event Added" });
});

/**
 * Get identity records from IPFS
 */
app.get("/api/v1/getIdentities:id", async (req, res) => {
  const id = req.params.id;
  try {
    if (!id) {
      return res.status(400).json({ error: "No Request Param" });
    }
    console.log(id);
    const { data: existingRecord, error } = await supabase
      .from("ipfs_records")
      .select("name, cid, revision")
      .eq("address", id);

    if (error) {
      return res.status(500).json({ error: "Query Error" });
    }
    console.log(existingRecord);

    if (existingRecord.length === 0) {
      return res.status(204).json({ message: "No data found" });
    }
    return res.status(200).json(existingRecord);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});

/**
 * Save encrypted identity records to IPFS. Requires a signature of the hashed data to ensure only the owner can save data.
 */
app.post("/api/v1/saveIdentities", async (req, res) => {
  const data = req.body;
  try {
    if (!data) {
      return res.status(400).json({ error: "No Data" });
    }
    if (!data.signature) {
      return res.status(403).json({ error: "Missing Signature" });
    }

    const { data: existingRecord, error } = await supabase
      .from("ipfs_records")
      .select("*")
      .eq("address", data.address);

    let name;
    let newFile = false;
    if (existingRecord.length === 0) {
      name = await Name.create();
      newFile = true;
    } else {
      name = await Name.from(Buffer.from(existingRecord[0].nameKey, "base64"));
    }

    // const digest = ethers.utils.keccak256(
      //   Buffer.from(data.encryptedData, "utf-8")
      // );
    const prefix = Buffer.from('\x19Ethereum Signed Message:\n');
    const idsBuf = Buffer.from(data.encryptedData, 'utf-8');
    const hashToSign = ethers.utils.keccak256(idsBuf);
    const hashBuf = Buffer.from(hashToSign.slice(2), 'hex');
    const lengthBuf = Buffer.from(String(hashBuf.length));
    const arrBuf = Buffer.concat([prefix, lengthBuf, hashBuf]);
    const hash = ethers.utils.keccak256(arrBuf);
    // const digest = ethers.utils.hashMessage(Buffer.from(data.encryptedData, "utf-8"));
    const address = ethers.utils.recoverAddress(hash, data.signature);

    if (address !== data.address) {
      return res.status(403).json({ error: "Invalid Signature" });
    }

    const buffer = Buffer.from(data.encryptedData);
    const file = new File([buffer], "data.json", { type: "application/json" });
    const cid = await client.put([file]);
    console.log({ cid });

    let revision;
    if (newFile) {
      revision = await Name.v0(name, `/ipfs/${cid}`);
      await Name.publish(revision, name.key);
    } else {
      revision = await Name.resolve(name);
      const nextRevision = await Name.increment(revision, `/ipfs/${cid}`);
      await Name.publish(nextRevision, name.key);
      // console.log({ nextRevision });
      revision = nextRevision;
    }
    console.log({ revision });

    const toWrite = {
      cid,
      address: data.address,
      updated_at: new Date().toISOString(),
      name: name.toString(),
      nameKey: name.key.bytes.toString("base64"),
      revision: revision.value,
    };
    console.log(toWrite);

    const { error: insertError } = await supabase
      .from("ipfs_records")
      .upsert(toWrite, { onConflict: "address" });

    if (insertError) {
      console.error(insertError);
      return res.status(500).json({ error: "Save Data Error" });
    }
    // return res.status(200).json({ cid });
    return res
      .status(200)
      .json({ cid, name: name.toString(), revision: revision.value });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});

/**
 * Start Listening
 */
app.listen(port, () => {
  console.log("signata-id-broker started on port 3000");
});
