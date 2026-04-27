import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;


public class DataOwner {



    private static final int DIGEST_BYTE_L = 8;
    private static final int LWE_DIMENSION = 1024;
    private static final long LWE_MODULUS = 1L << 32;


    private int n;
    private int valueByteLength;
    private int partition;
    private int binNum;
    private int maxBinSize;
    private byte[] hashKey;
    private List<List<Entry>> bins;
    private byte[][][] database;
    private byte[][][] proofMatrix;
    private byte[] merkleRoot;
    private byte[] seed;
    private int[][] matrixA;
    private int[][] hint1;
    private int[][] hint2;
    private int proofRows;
    private SecureRandom secureRandom;



    public static class Entry {
        byte[] key;
        byte[] data;

        public Entry(byte[] key, byte[] data) {
            this.key = key;
            this.data = data;
        }
    }



    public DataOwner() {
        this.secureRandom = new SecureRandom();
    }

    // Hash分桶

    public void task1_HashBinning(Map<byte[], byte[]> keyValueMap, int valueByteLength) throws Exception {
        System.out.println("========== Task 1: Hash Binning + Padding ==========");

        this.n = keyValueMap.size();
        this.valueByteLength = valueByteLength;
        this.partition = valueByteLength + DIGEST_BYTE_L;

        int initialBinNum = (int) Math.ceil(Math.sqrt((long) n * (long) partition));
        this.binNum = initialBinNum;

        System.out.println("  - Database size N = " + n);
        System.out.println("  - Value length = " + valueByteLength + " bytes");
        System.out.println("  - Partition = " + partition + " bytes");
        System.out.println("  - binNum = " + binNum);

        calculateProofRows();

        this.hashKey = new byte[16];
        secureRandom.nextBytes(hashKey);

        performHashBinning(keyValueMap);

        System.out.println("  - maxBinSize = " + maxBinSize + ", proofRows = " + proofRows);

        fillDummyElements();
        buildDataMatrix();

        System.out.println("========== Task 1 Completed ==========\n");
    }

    private void calculateProofRows() {
        int treeHeight = (int) Math.ceil(Math.log(binNum) / Math.log(2));
        int proofLength = treeHeight * 32;
        this.proofRows = (int) Math.ceil((double) proofLength / partition);
    }

    private void performHashBinning(Map<byte[], byte[]> keyValueMap) throws Exception {
        this.bins = new ArrayList<>(binNum);
        for (int i = 0; i < binNum; i++) {
            bins.add(new ArrayList<>());
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        for (Map.Entry<byte[], byte[]> entry : keyValueMap.entrySet()) {
            byte[] key = entry.getKey();
            byte[] value = entry.getValue();

            byte[] keyHash = digest.digest(key);
            byte[] keyDigest = Arrays.copyOf(keyHash, DIGEST_BYTE_L);

            byte[] item = new byte[partition];
            System.arraycopy(keyDigest, 0, item, 0, DIGEST_BYTE_L);
            System.arraycopy(value, 0, item, DIGEST_BYTE_L, valueByteLength);

            int binIndex = prfGetInteger(key, binNum);
            bins.get(binIndex).add(new Entry(key, item));
        }

        this.maxBinSize = 0;
        for (int i = 0; i < binNum; i++) {
            int size = bins.get(i).size();
            if (size > maxBinSize) {
                maxBinSize = size;
            }
        }
    }

    private void fillDummyElements() {
        for (int i = 0; i < binNum; i++) {
            int currentSize = bins.get(i).size();
            int paddingCount = maxBinSize - currentSize;
            for (int j = 0; j < paddingCount; j++) {
                byte[] dummyItem = new byte[partition];
                secureRandom.nextBytes(dummyItem);
                bins.get(i).add(new Entry(null, dummyItem));
            }
        }
    }

    private void buildDataMatrix() {
        this.database = new byte[maxBinSize][binNum][partition];
        for (int col = 0; col < binNum; col++) {
            List<Entry> bin = bins.get(col);
            for (int row = 0; row < maxBinSize; row++) {
                System.arraycopy(bin.get(row).data, 0, database[row][col], 0, partition);
            }
        }
    }

    //  Merkle

    public void task2_BuildMerkleTree() throws Exception {
        System.out.println("========== Task 2: Build Merkle Tree ==========");

        byte[][] leaves = computeMerkleLeaves();
        List<List<byte[]>> allLevels = buildMerkleTree(leaves);
        byte[][] merkleProofs = generateMerkleProofs(allLevels);
        byte[][][] proofBlocks = splitProofsIntoBlocks(merkleProofs);
        buildProofMatrix(proofBlocks);

        System.out.println("========== Task 2 Completed ==========\n");
    }

    private byte[][] computeMerkleLeaves() throws Exception {
        byte[][] leaves = new byte[binNum][32];
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (int col = 0; col < binNum; col++) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (int row = 0; row < maxBinSize; row++) {
                baos.write(database[row][col]);
            }
            leaves[col] = sha256.digest(baos.toByteArray());
        }
        return leaves;
    }

    private List<List<byte[]>> buildMerkleTree(byte[][] leaves) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        List<List<byte[]>> allLevels = new ArrayList<>();

        List<byte[]> currentLevel = new ArrayList<>();
        for (byte[] leaf : leaves) {
            currentLevel.add(leaf);
        }
        allLevels.add(new ArrayList<>(currentLevel));

        while (currentLevel.size() > 1) {
            List<byte[]> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                byte[] left = currentLevel.get(i);
                byte[] right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;

                sha256.reset();
                sha256.update(left);
                sha256.update(right);
                nextLevel.add(sha256.digest());
            }
            currentLevel = nextLevel;
            allLevels.add(new ArrayList<>(currentLevel));
        }

        this.merkleRoot = currentLevel.get(0);
        System.out.println("  - Merkle Root: " + bytesToHex(merkleRoot));
        return allLevels;
    }

    private byte[][] generateMerkleProofs(List<List<byte[]>> allLevels) throws Exception {
        int treeHeight = allLevels.size() - 1;
        int proofLength = treeHeight * 32;
        byte[][] merkleProofs = new byte[binNum][proofLength];

        for (int leafIndex = 0; leafIndex < binNum; leafIndex++) {
            ByteArrayOutputStream proof = new ByteArrayOutputStream();
            int currentIndex = leafIndex;

            for (int level = 0; level < allLevels.size() - 1; level++) {
                List<byte[]> currentLevelNodes = allLevels.get(level);
                int siblingIndex = (currentIndex % 2 == 0) ? currentIndex + 1 : currentIndex - 1;

                byte[] sibling;
                if (siblingIndex < currentLevelNodes.size()) {
                    sibling = currentLevelNodes.get(siblingIndex);
                } else {
                    sibling = currentLevelNodes.get(currentIndex);
                }
                proof.write(sibling);
                currentIndex = currentIndex / 2;
            }
            merkleProofs[leafIndex] = proof.toByteArray();
        }
        return merkleProofs;
    }

    private byte[][][] splitProofsIntoBlocks(byte[][] merkleProofs) {
        byte[][][] proofBlocks = new byte[binNum][proofRows][partition];

        for (int col = 0; col < binNum; col++) {
            byte[] proof = merkleProofs[col];
            for (int block = 0; block < proofRows; block++) {
                int start = block * partition;
                int end = Math.min(start + partition, proof.length);
                int copyLen = end - start;
                System.arraycopy(proof, start, proofBlocks[col][block], 0, copyLen);
                if (copyLen < partition) {
                    Arrays.fill(proofBlocks[col][block], copyLen, partition, (byte) 0);
                }
            }
        }
        return proofBlocks;
    }

    private void buildProofMatrix(byte[][][] proofBlocks) {
        this.proofMatrix = new byte[maxBinSize][binNum][partition];

        for (int col = 0; col < binNum; col++) {
            for (int row = 0; row < proofRows; row++) {
                proofMatrix[row][col] = proofBlocks[col][row];
            }
        }

        // Pad remaining rows with random data
        for (int row = proofRows; row < maxBinSize; row++) {
            for (int col = 0; col < binNum; col++) {
                secureRandom.nextBytes(proofMatrix[row][col]);
            }
        }
    }

    // Hint

    public void task3_GenerateHints() throws Exception {
        System.out.println("========== Task 3: Generate Hints ==========");
        generateMatrixA();
        computeHint1();
        computeHint2();
        System.out.println("========== Task 3 Completed ==========\n");
    }

    private void generateMatrixA() {
        this.seed = new byte[16];
        secureRandom.nextBytes(seed);

        this.matrixA = new int[LWE_DIMENSION][binNum];
        java.util.Random rng = new java.util.Random(bytesToLong(seed));

        for (int i = 0; i < LWE_DIMENSION; i++) {
            rng.setSeed(bytesToLong(seed) + i);
            for (int j = 0; j < binNum; j++) {
                matrixA[i][j] = rng.nextInt();
            }
        }
    }

    private void computeHint1() {
        long startTime = System.currentTimeMillis();
        int hintCols = maxBinSize * partition;
        hint1 = new int[LWE_DIMENSION][hintCols];

        int numThreads = Runtime.getRuntime().availableProcessors();
        Thread[] threads = new Thread[numThreads];
        int rowsPerThread = (LWE_DIMENSION + numThreads - 1) / numThreads;

        for (int t = 0; t < numThreads; t++) {
            final int startRow = t * rowsPerThread;
            final int endRow = Math.min(startRow + rowsPerThread, LWE_DIMENSION);

            threads[t] = new Thread(() -> {
                for (int i = startRow; i < endRow; i++) {
                    int[] aRow = matrixA[i];
                    for (int row = 0; row < maxBinSize; row++) {
                        for (int bytePos = 0; bytePos < partition; bytePos++) {
                            long sum = 0;
                            for (int j = 0; j < binNum; j++) {
                                sum += (long) aRow[j] * (database[row][j][bytePos] & 0xFF);
                            }
                            hint1[i][row * partition + bytePos] = (int) (sum % LWE_MODULUS);
                        }
                    }
                }
            });
            threads[t].start();
        }

        try {
            for (Thread thread : threads) thread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("  - Hint1 computed in " + (System.currentTimeMillis() - startTime) + " ms");
    }

    private void computeHint2() {
        long startTime = System.currentTimeMillis();
        int hintCols = maxBinSize * partition;
        hint2 = new int[LWE_DIMENSION][hintCols];

        int numThreads = Runtime.getRuntime().availableProcessors();
        Thread[] threads = new Thread[numThreads];
        int rowsPerThread = (LWE_DIMENSION + numThreads - 1) / numThreads;

        for (int t = 0; t < numThreads; t++) {
            final int startRow = t * rowsPerThread;
            final int endRow = Math.min(startRow + rowsPerThread, LWE_DIMENSION);

            threads[t] = new Thread(() -> {
                for (int i = startRow; i < endRow; i++) {
                    int[] aRow = matrixA[i];
                    for (int row = 0; row < maxBinSize; row++) {
                        for (int bytePos = 0; bytePos < partition; bytePos++) {
                            long sum = 0;
                            for (int j = 0; j < binNum; j++) {
                                sum += (long) aRow[j] * (proofMatrix[row][j][bytePos] & 0xFF);
                            }
                            hint2[i][row * partition + bytePos] = (int) (sum % LWE_MODULUS);
                        }
                    }
                }
            });
            threads[t].start();
        }

        try {
            for (Thread thread : threads) thread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("  - Hint2 computed in " + (System.currentTimeMillis() - startTime) + " ms");
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

    private long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < Math.min(8, bytes.length); i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
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
    public int getProofRows() { return proofRows; }
    public int getPartition() { return partition; }
    public byte[] getHashKey() { return hashKey; }
    public byte[][][] getDatabase() { return database; }
    public byte[][][] getProofMatrix() { return proofMatrix; }
    public byte[] getMerkleRoot() { return merkleRoot; }
    public byte[] getSeed() { return seed; }
    public int[][] getHint1() { return hint1; }
    public int[][] getHint2() { return hint2; }
    public int[][] getMatrixA() { return matrixA; }

    public int getKeyBinIndex(byte[] key) { return prfGetInteger(key, binNum); }

    public byte[][] getBinData(int binIndex) {
        if (binIndex < 0 || binIndex >= binNum) return null;
        byte[][] binData = new byte[maxBinSize][partition];
        for (int row = 0; row < maxBinSize; row++) {
            binData[row] = database[row][binIndex];
        }
        return binData;
    }
}
