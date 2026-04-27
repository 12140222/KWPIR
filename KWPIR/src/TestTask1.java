import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;


public class TestTask1 {

    public static void main(String[] args) {
        try {
            System.out.println("========================================");
            System.out.println("  测试 Task 1 / 2 / 3 预处理");
            System.out.println("========================================\n");

            int N = 256;
            int valueByteLength = 32;

            Map<byte[], byte[]> keyValueMap = generateTestData(N, valueByteLength);
            System.out.println("Generated " + N + " key-value pairs\n");

            DataOwner dataOwner = new DataOwner();
            dataOwner.task1_HashBinning(keyValueMap, valueByteLength);
            dataOwner.task2_BuildMerkleTree();
            dataOwner.task3_GenerateHints();

            System.out.println("========================================");
            System.out.println("  Results Summary");
            System.out.println("========================================");
            System.out.println("  Data Matrix: " + dataOwner.getMaxBinSize() + " x " +
                dataOwner.getBinNum() + " x " + dataOwner.getPartition());
            System.out.println("  Proof Matrix: " + dataOwner.getMaxBinSize() + " x " +
                dataOwner.getBinNum() + " x " + dataOwner.getPartition());
            int totalStorage = 2 * dataOwner.getMaxBinSize() * dataOwner.getBinNum() * dataOwner.getPartition();
            System.out.println("  Server Storage: " + totalStorage + " bytes (" + (totalStorage / 1024) + " KB)");
            System.out.println("\nDone.");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Map<byte[], byte[]> generateTestData(int n, int valueByteLength) {
        Map<byte[], byte[]> map = new HashMap<>();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < n; i++) {
            byte[] key = new byte[16];
            random.nextBytes(key);
            byte[] value = new byte[valueByteLength];
            random.nextBytes(value);
            map.put(key, value);
        }
        return map;
    }
}
