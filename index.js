const express = require('express');
const ethers = require('ethers');
const { createHmac } = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const signingAuthority = process.env.SIGNING_KEY;
const TXTYPE_CLAIM_DIGEST = process.env.TXTYPE_CLAIM_DIGEST;
const DOMAIN_SEPARATOR = process.env.DOMAIN_SEPARATOR;
const BLOCKPASS_SECRET = process.env.BLOCKPASS_SECRET;

const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => {
  res.send({ service: "signata-id-broker", version: "0.0.1" });
});

app.get('/api/v1/requestKyc/:id', async (req, res) => {
  const { data, error } = await supabase.from('blockpass_events').select("*").eq("refId", req.params.id);

  if (error) {
    console.error(error);
    return res.status(500).json({ error: "Events Error" });
  }
  if (data.length === 0) {
    return res.status(204).json({ message: 'No data found' });
  } else {
    // find an existing signature
    const { data: existingRecord, error: existingRecordError } = await supabase.from('kyc_claims').select("signature").eq("identity", req.params.id);
    
    if (existingRecordError) {
      console.error(existingRecordError);
      return res.status(500).json({ error: "Existing Record Error" });
    }

    if (existingRecord.length === 0) {
      console.log('no existing record, creating new one');
      // generate a new signature
      const inputHash = ethers.utils.keccak256(
        `${TXTYPE_CLAIM_DIGEST}${req.params.id.slice(2).padStart(64, '0')}`,
      );
      const hashToSign = ethers.utils.keccak256(`0x1901${DOMAIN_SEPARATOR.slice(2)}${inputHash.slice(2)}`);
      const signature = new ethers.utils.SigningKey(signingAuthority).signDigest(hashToSign);

      const { error: insertError } = await supabase.from('kyc_claims').insert({ identity: req.params.id, signature: signature.compact });

      if (insertError) {
        console.error(insertError);
        return res.status(500).json({ error: "Insert Error" });
      }

      return res.status(200).json({ signature: signature.compact });
    } else {
      // return the existing signature
      console.log('found existing record');
      return res.status(200).json({ signature: existingRecord[0].signature });
    }
  }
});

app.post("/api/v1/blockpassWebhook", async (req, res) => {
  const data = req.body;

  if (!data) {
    return res.status(400).json({ error: "No Data" });
  }
  console.log(data);

  const requestSignature = req.get('X-Hub-Signature');
  const algo = 'sha256';
  const hmac = createHmac(algo, BLOCKPASS_SECRET);
  hmac.update(JSON.stringify(data));
  const result = hmac.digest('hex');

  if (result === requestSignature) {
    const { error } = await supabase.from('blockpass_events').insert(data);
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Events Error" });
    }
    return res.status(200).json({ message: 'Event Added' });
  } else {
    console.log({
      message: 'signature verification failed',
      requestSignature,
      result
    });
    return res.status(403).json({ error: "Invalid Signature" });
  }
});

app.listen(port, () => {
  console.log('signata-id-broker started on port 3000');
});
