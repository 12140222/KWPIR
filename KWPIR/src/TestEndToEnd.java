import java.util.*;


public class TestEndToEnd {

    public static void main(String[] args) {
        try {
            System.out.println("========================================");
            System.out.println("  End-to-End Test: KWpir");
            System.out.println("========================================\n");

            int N = 1024;
            int valueByteLength = 32;

            // Generate test database
            Map<byte[], byte[]> database = generateTestDatabase(N, valueByteLength);
            byte[] testKey = database.keySet().iterator().next();
            byte[] expectedValue = database.get(testKey);

            System.out.println("Database size: " + N);
            System.out.println("Test key: " + bytesToHex(testKey));
            System.out.println("Expected value: " + bytesToHex(expectedValue) + "\n");

            // Data Owner Preprocessing
            long t0 = System.currentTimeMillis();
            DataOwner dataOwner = new DataOwner();
            dataOwner.task1_HashBinning(database, valueByteLength);
            dataOwner.task2_BuildMerkleTree();
            dataOwner.task3_GenerateHints();
            long t1 = System.currentTimeMillis();
            System.out.println("Preprocessing: " + (t1 - t0) + " ms\n");

            //  Server Init
            Server server = new Server();
            server.initialize(dataOwner.getDatabase(), dataOwner.getProofMatrix());

            //Client Init
            Client client = new Client();
            client.initialize(
                dataOwner.getHashKey(), dataOwner.getBinNum(), dataOwner.getMaxBinSize(),
                dataOwner.getPartition(), dataOwner.getMatrixA(),
                dataOwner.getHint1(), dataOwner.getHint2(),
                dataOwner.getMerkleRoot(), dataOwner.getProofRows());

            //  Query Phase
            long t2 = System.currentTimeMillis();
            int[] queryVector = client.generateQuery(testKey);
            long t3 = System.currentTimeMillis();

            Server.ServerResponse response = server.processQuery(queryVector);
            long t4 = System.currentTimeMillis();

            byte[] retrievedValue = client.decodeAndVerify(
                response.getResponse1(), response.getResponse2(), testKey);
            long t5 = System.currentTimeMillis();

            //  Results
            System.out.println("\n========================================");
            System.out.println("  Timing");
            System.out.println("========================================");
            System.out.println("  Query generation: " + (t3 - t2) + " ms");
            System.out.println("  Server processing: " + (t4 - t3) + " ms");
            System.out.println("  Decode & verify: " + (t5 - t4) + " ms");

            System.out.println("\n========================================");
            System.out.println("  Verification");
            System.out.println("========================================");
            if (retrievedValue != null && Arrays.equals(retrievedValue, expectedValue)) {
                System.out.println("  SUCCESS: Retrieved value matches expected value.");
            } else {
                System.out.println("  FAILED: Value mismatch or not found.");
                if (retrievedValue != null) {
                    System.out.println("  Expected:  " + bytesToHex(expectedValue));
                    System.out.println("  Retrieved: " + bytesToHex(retrievedValue));
                }
            }

        } catch (Exception e) {
            System.err.println("Test failed:");
            e.printStackTrace();
        }
    }

    private static Map<byte[], byte[]> generateTestDatabase(int n, int valueByteLength) {
        Map<byte[], byte[]> db = new LinkedHashMap<>();
        Random random = new Random(12345);
        for (int i = 0; i < n; i++) {
            byte[] key = new byte[16];
            random.nextBytes(key);
            byte[] value = new byte[valueByteLength];
            random.nextBytes(value);
            db.put(key, value);
        }
        return db;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 16); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > 16) sb.append("...");
        return sb.toString();
    }
}
