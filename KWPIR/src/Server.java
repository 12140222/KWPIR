/**
 * Server - Handles query processing and response generation
 */
public class Server {

    private static final long LWE_MODULUS = 1L << 32;

    private byte[][][] dataMatrix;
    private byte[][][] proofMatrix;
    private int binNum;
    private int proofRows;
    private int partition;

    public Server() {}

    public void initialize(byte[][][] dataMatrix, byte[][][] proofMatrix) {
        this.dataMatrix = dataMatrix;
        this.proofMatrix = proofMatrix;
        this.proofRows = dataMatrix.length;
        this.binNum = dataMatrix[0].length;
        this.partition = dataMatrix[0][0].length;

        System.out.println("Server initialized:");
        System.out.println("  - Matrix dimensions: " + proofRows + " x " + binNum + " x " + partition);
        System.out.println("  - Total storage: " + (2 * proofRows * binNum * partition / 1024) + " KB");
    }

    public ServerResponse processQuery(int[] queryVector) throws Exception {
        if (queryVector.length != binNum) {
            throw new IllegalArgumentException(
                "Invalid query vector dimension: expected " + binNum + ", got " + queryVector.length);
        }

        long t1 = System.currentTimeMillis();
        int[][] response1 = matrixVectorMultiply(queryVector, dataMatrix);
        long t2 = System.currentTimeMillis();
        int[][] response2 = matrixVectorMultiply(queryVector, proofMatrix);
        long t3 = System.currentTimeMillis();

        System.out.println("Server query processed: data=" + (t2 - t1) + "ms, proof=" + (t3 - t2) + "ms");

        return new ServerResponse(response1, response2);
    }

    private int[][] matrixVectorMultiply(int[] queryVector, byte[][][] matrix) {
        int[][] result = new int[proofRows][partition];

        for (int row = 0; row < proofRows; row++) {
            for (int bytePos = 0; bytePos < partition; bytePos++) {
                long sum = 0;
                for (int col = 0; col < binNum; col++) {
                    sum += (long) queryVector[col] * (matrix[row][col][bytePos] & 0xFF);
                }
                result[row][bytePos] = (int) (sum % LWE_MODULUS);
            }
        }
        return result;
    }

    // Inner Class

    public static class ServerResponse {
        private int[][] response1;
        private int[][] response2;

        public ServerResponse(int[][] response1, int[][] response2) {
            this.response1 = response1;
            this.response2 = response2;
        }

        public int[][] getResponse1() { return response1; }
        public int[][] getResponse2() { return response2; }

        public int getTotalSize() {
            return (response1.length * response1[0].length + response2.length * response2[0].length) * 4;
        }
    }

    public int getBinNum() { return binNum; }
    public int getProofRows() { return proofRows; }
    public int getPartition() { return partition; }
}
