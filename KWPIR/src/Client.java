import java.security.MessageDigest;
import java.security.SecureRandom;


public class Client {

    private static final int LWE_DIMENSION = 1024;
    private static final long LWE_MODULUS = 1L << 32;
    private static final double NOISE_STDDEV = 6.4;
    private static final int DELTA = 1 << 20;

    private byte[] hashKey;
    private int binNum;
    private int maxBinSize;
    private int partition;
    private int[][] matrixA;
    private int[][] hint1;
    private int[][] hint2;
    private byte[] merkleRoot;
    private int proofRows;

    private SecureRandom secureRandom;
    private int[] secretVector;
    private int targetBinIndex;

    public Client() {
        this.secureRandom = new SecureRandom();
    }

    public void initialize(byte[] hashKey, int binNum, int maxBinSize, int partition,
                           int[][] matrixA, int[][] hint1, int[][] hint2,
                           byte[] merkleRoot, int proofRows) {
        this.hashKey = hashKey;
        this.binNum = binNum;
        this.maxBinSize = maxBinSize;
        this.partition = partition;
        this.matrixA = matrixA;
        this.hint1 = hint1;
        this.hint2 = hint2;
        this.merkleRoot = merkleRoot;
        this.proofRows = proofRows;

        System.out.println("Client initialized: binNum=" + binNum +
            ", maxBinSize=" + maxBinSize + ", partition=" + partition + ", proofRows=" + proofRows);
    }

    // Query Generation

    public int[] generateQuery(byte[] queryKey) throws Exception {
        int targetBinIndex = prfGetInteger(queryKey, binNum);
        this.targetBinIndex = targetBinIndex;

        this.secretVector = new int[LWE_DIMENSION];
        for (int i = 0; i < LWE_DIMENSION; i++) {
            secretVector[i] = sampleGaussianNoise();
        }

        int[] sA = new int[binNum];
        for (int j = 0; j < binNum; j++) {
            long sum = 0;
            for (int i = 0; i < LWE_DIMENSION; i++) {
                sum += (long) secretVector[i] * matrixA[i][j];
            }
            sA[j] = (int) (sum % LWE_MODULUS);
        }

        int[] queryVector = new int[binNum];
        for (int i = 0; i < binNum; i++) {
            int noise = sampleGaussianNoise();
            if (i == targetBinIndex) {
                queryVector[i] = (int) ((sA[i] + noise + DELTA) % LWE_MODULUS);
            } else {
                queryVector[i] = (int) ((sA[i] + noise) % LWE_MODULUS);
            }
        }

        System.out.println("Query generated: targetBin=" + targetBinIndex + ", dimension=" + binNum);
        return queryVector;
    }

    private int sampleGaussianNoise() {
        double u1 = secureRandom.nextDouble();
        double u2 = secureRandom.nextDouble();
        while (u1 == 0.0) u1 = secureRandom.nextDouble();
        double z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
        return (int) Math.round(z0 * NOISE_STDDEV);
    }

    private int prfGetInteger(byte[] input, int bound) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(hashKey);
            md.update(input);
            byte[] hash = md.digest();
            int value = ((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16) |
                        ((hash[2] & 0xFF) << 8) | (hash[3] & 0xFF);
            return Math.abs(value) % bound;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //Decoding and Verification

    public byte[] decodeAndVerify(int[][] response1, int[][] response2, byte[] queryKey) throws Exception {
        final byte[][] results = new byte[2][];
        final Exception[] exceptions = new Exception[2];

        Thread t1 = new Thread(() -> {
            try { results[1] = decodeResponse(response2, hint2); }
            catch (Exception e) { exceptions[0] = e; }
        });
        Thread t2 = new Thread(() -> {
            try { results[0] = decodeResponse(response1, hint1); }
            catch (Exception e) { exceptions[1] = e; }
        });

        t1.start(); t2.start();
        t1.join(); t2.join();

        if (exceptions[0] != null) throw exceptions[0];
        if (exceptions[1] != null) throw exceptions[1];

        byte[] bucketData = results[0];
        byte[] verificationPath = results[1];

        boolean verified = verifyMerkleProof(bucketData, verificationPath);
        if (!verified) {
            System.out.println("  Merkle verification FAILED!");
            return null;
        }
        System.out.println("  Merkle verification PASSED");

        return extractValue(bucketData, queryKey);
    }

    private byte[] decodeResponse(int[][] response, int[][] hint) {
        int responseSize = response.length * response[0].length;
        long[] sHint = new long[responseSize];

        for (int i = 0; i < responseSize; i++) {
            long sum = 0;
            for (int j = 0; j < LWE_DIMENSION; j++) {
                sum += (long) secretVector[j] * hint[j][i];
            }
            sHint[i] = sum;
        }

        byte[] decoded = new byte[responseSize];
        int idx = 0;
        for (int row = 0; row < response.length; row++) {
            for (int col = 0; col < response[0].length; col++) {
                long responseValue = response[row][col] & 0xFFFFFFFFL;
                long diff = responseValue - (sHint[idx] % LWE_MODULUS);
                while (diff < 0) diff += LWE_MODULUS;
                diff = diff % LWE_MODULUS;

                long decodedValue = Math.round((double) diff / DELTA) % 256;
                if (decodedValue < 0) decodedValue += 256;
                decoded[idx] = (byte) decodedValue;
                idx++;
            }
        }
        return decoded;
    }

    private boolean verifyMerkleProof(byte[] bucketData, byte[] encodedProof) throws Exception {
        int treeHeight = (int) Math.ceil(Math.log(binNum) / Math.log(2));
        int actualProofLength = treeHeight * 32;

        byte[] verificationPath = new byte[actualProofLength];
        int srcIdx = 0, dstIdx = 0;
        for (int block = 0; block < proofRows; block++) {
            int copyLen = Math.min(partition, actualProofLength - dstIdx);
            System.arraycopy(encodedProof, srcIdx, verificationPath, dstIdx, copyLen);
            srcIdx += partition;
            dstIdx += copyLen;
            if (dstIdx >= actualProofLength) break;
        }

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] currentHash = sha256.digest(bucketData);

        byte[][] siblings = new byte[treeHeight][32];
        for (int i = 0; i < treeHeight; i++) {
            System.arraycopy(verificationPath, i * 32, siblings[i], 0, 32);
        }

        int leafIndex = this.targetBinIndex;
        for (int level = 0; level < treeHeight; level++) {
            sha256.reset();
            if (leafIndex % 2 == 0) {
                sha256.update(currentHash);
                sha256.update(siblings[level]);
            } else {
                sha256.update(siblings[level]);
                sha256.update(currentHash);
            }
            currentHash = sha256.digest();
            leafIndex = leafIndex / 2;
        }

        return java.util.Arrays.equals(currentHash, merkleRoot);
    }

    private byte[] extractValue(byte[] bucketData, byte[] queryKey) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] queryKeyDigest = java.util.Arrays.copyOf(sha256.digest(queryKey), 8);

        int entrySize = partition;
        int numEntries = bucketData.length / entrySize;

        for (int i = 0; i < numEntries; i++) {
            int offset = i * entrySize;
            byte[] entryKeyHash = new byte[8];
            System.arraycopy(bucketData, offset, entryKeyHash, 0, 8);

            if (java.util.Arrays.equals(entryKeyHash, queryKeyDigest)) {
                byte[] value = new byte[32];
                System.arraycopy(bucketData, offset + 8, value, 0, 32);
                return value;
            }
        }
        return null;
    }


    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 8); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > 8) sb.append("...");
        return sb.toString();
    }

    public int getBinNum() { return binNum; }
    public int getMaxBinSize() { return maxBinSize; }
}
