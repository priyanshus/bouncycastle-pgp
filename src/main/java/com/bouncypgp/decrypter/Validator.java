package com.tw;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class Validator {
    public Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    public List<PGPOnePassSignature> verifiedOps = new ArrayList<PGPOnePassSignature>();
    public PublicKeyConfig publicKeyConfig;

    public Validator(PublicKeyConfig publicKeyConfig) {
        this.publicKeyConfig = publicKeyConfig;
    }

    public List<PGPOnePassSignature> verifyOnePassSignatureKeyId(PGPOnePassSignatureList opsList) throws PGPException {
        for (PGPPublicKey publicKey : publicKeyConfig.getPublicKeys()) {
            boolean verified = false;
            for (PGPOnePassSignature ops : opsList) {
                ops.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                if (ops.getKeyID() == publicKey.getKeyID()) {
                    logger.info("OnePassSignature with Key: " + getHex(ops.getKeyID()) + " verified with Public Key: " + getHex(ops.getKeyID()));
                    verifiedOps.add(ops);
                    verified = true;
                }
            }

            if(!verified) {
                throw new PGPException("Not able to verify one pass signature for " + getHex(publicKey.getKeyID()));
            }
        }

        logger.info("Found " + verifiedOps.size() + " verified one pass signatures");
        return verifiedOps;
    }


    public List<PGPSignature> verifySignaturePackets(byte[] bytes, List<PGPOnePassSignature> opsList , PGPSignatureList signList) throws PGPException {
        List<PGPSignature> verifiedSignatures = new ArrayList<>();
        logger.info("Found " + signList.size() + " signature packets");

        for (PGPOnePassSignature onePassSignature: opsList) {
            PGPOnePassSignature tempOnePassSign = onePassSignature;
            tempOnePassSign.update(bytes);
            for (PGPSignature signature: signList) {
                logger.info("Verifying signature packet :" + getHex(signature.getKeyID()));
                if(tempOnePassSign.verify(signature)) {
                    logger.info("Added signature packet in verified bucket:" + getHex(signature.getKeyID()));
                    verifiedSignatures.add(signature);
                }else {
                    tempOnePassSign = onePassSignature;
                    tempOnePassSign.update(bytes);
                }
            }
        }

        if(!verifiedSignatures.isEmpty()) {
            return verifiedSignatures;
        }else {
            throw new PGPException("Not able to verify any of the signature");
        }
    }

    public String getHex(Long l) {
        return Long.toHexString(l);
    }
}
