import com.trinoudf.crypto.AESCBCDecrypter;
import com.trinoudf.crypto.AESCBCEncrypter;
import com.trinoudf.crypto.Decoder;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Properties;

import static io.airlift.slice.Slices.wrappedBuffer;

import static org.junit.Assert.assertEquals;

/**
 * ==Description==
 * <p>
 *     Unit Test for AES CBC encryption and decryption methods.
 * </p>
 * <br/>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated</p>
 * <br/>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>aesCBCEncryptDecryptString()</li>
 *     <li>aesCBCEncryptDecryptByteBuffer()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class UnitTest {
    /**
     * Unit test for AES CBC encryption and decryption of String.
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @author Wong Kok-Lim
     */
    @Test
    public void aesCBCEncryptDecryptString() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String expected = "hello2";

        String encrypt = new AESCBCEncrypter().encryptString(expected, "aesEncryptionKey", "encryptionIntVec");

        String decrypt = new AESCBCDecrypter().decryptString(encrypt, "aesEncryptionKey", "encryptionIntVec");
        String decryptStr = decrypt;

        assertEquals(expected, decryptStr);
    }

    /**
     * Unit test for AES CBC encryption and decryption of ByteBuffer.
     * @author Wong Kok-Lim
     */
    @Test
    public void aesCBCEncryptDecryptByteBuffer() {
        String expected = "hello2";

        ByteBuffer encrypt = new AESCBCEncrypter().encryptByteBuffer(ByteBuffer.wrap(expected.getBytes()), "aesEncryptionKey", "encryptionIntVec");
        String encryptedStr = wrappedBuffer(encrypt).toStringUtf8();

        ByteBuffer decrypt = new AESCBCDecrypter().decryptByteBuffer(ByteBuffer.wrap(Decoder.decode(encryptedStr)), "aesEncryptionKey", "encryptionIntVec");
        String decryptStr = wrappedBuffer(decrypt).toStringAscii().trim();

        assertEquals(expected, decryptStr);
    }

    /** Unit test for JDBC connection to Trino.
     * @author Wong Kok-Lim
     */
    @Test
    public void testJdbc() throws SQLException {
        Connection connection = jdbcConnection();
        Statement stmt = getStatement(connection);
        ResultSet res = stmt.executeQuery("SELECT * FROM ipaddress_encrypt_256_65536");

        try {
            res.next();
            assertEquals("M/cxFtUM1jaL/WWtGNLKnvcuPLHcESKcvnh7TYp4Awg=", res.getString("ipaddress_val"));
        }
        catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        finally {
            connection.close();
            stmt.close();
            res.close();
        }
    }

    /**
     * Bulk load 100 records to Kudu via Trino.
     * @author Wong Kok-Lim
     */
    @Test
    public void testBulkLoad100() throws SQLException {
        Connection connection = jdbcConnection();
        Statement stmt = getStatement(connection);
        String sql = "INSERT INTO bulk_100 VALUES(|row|,'os5wRVI8BhjtLUNhisuOA4trKjTPC6/FX+vvIrqlMeU=','Cx9kazlF9iBX8+GstGfzmg=','On46L6igJQl7PZ/snBPoZA==','On46L6igJQl7PZ/snBPoZA==','On46L6igJQl7PZ/snBPoZA==','GhgsnLAyrvt/cFubrTTJJg==','YePvTywrn1cI/uaz67Y7tA==','0rx4QxnflHc5ih1ledOZ1w==','T0b56F3RG+bNxvjIZ6xBOQ==','Fc+x3DhB8uKSRRxEzOTFXQ==','aEShsTcK6h8SpcOYC4xjJQ==','M/cxFtUM1jaL/WWtGNLKnvcuPLHcESKcvnh7TYp4Awg=','wwn+Xc80NKR8Rhnz/mtC3M8qXlr4wRTq/36kOgp0WBI=','T0b56F3RG+bNxvjIZ6xBOQ==')";

        for(int i = 0; i < 100; i++) {
            try {
                stmt.addBatch(sql.replace("|row|", String.valueOf(i)));
            }
            catch (SQLException e) {
                assertEquals("Batches not supported", e.getMessage());
            }
        }

        int[] res = new int[0];
        try {
            res = stmt.executeBatch();
        }
        catch (SQLException throwables) {
            assertEquals("Batches not supported", throwables.getMessage());
            throwables.printStackTrace();
        }
        finally {
            connection.close();
            stmt.close();
        }
//        assertEquals(100, res.length);
    }

    /**
     * Stress Test for real time.
     * @author Wong Kok-Lim
     */
    @Test
    public void stressTestRealTime() throws SQLException {
        int i = 0;
        while(true) {
            Connection connection = jdbcConnection();
            Statement stmt = getStatement(connection);
            String sql = "INSERT INTO bulk_100 VALUES(|row|,'os5wRVI8BhjtLUNhisuOA4trKjTPC6/FX+vvIrqlMeU=','Cx9kazlF9iBX8+GstGfzmg=','On46L6igJQl7PZ/snBPoZA==','On46L6igJQl7PZ/snBPoZA==','On46L6igJQl7PZ/snBPoZA==','GhgsnLAyrvt/cFubrTTJJg==','YePvTywrn1cI/uaz67Y7tA==','0rx4QxnflHc5ih1ledOZ1w==','T0b56F3RG+bNxvjIZ6xBOQ==','Fc+x3DhB8uKSRRxEzOTFXQ==','aEShsTcK6h8SpcOYC4xjJQ==','M/cxFtUM1jaL/WWtGNLKnvcuPLHcESKcvnh7TYp4Awg=','wwn+Xc80NKR8Rhnz/mtC3M8qXlr4wRTq/36kOgp0WBI=','T0b56F3RG+bNxvjIZ6xBOQ==')";

            connection.setAutoCommit(false);
            try {
                stmt.execute(sql.replace("|row|", String.valueOf(i)));
                connection.commit();
                i++;
            }
            catch (SQLException throwables) {
                throwables.printStackTrace();
            }
            finally {
                connection.close();
                stmt.close();
            }
        }
    }

    /**
     * Creates a JDBC connection to a Trino server.
     * @return JDBC connection to specified Trino server.
     * @throws SQLException If connection is unable to be made witht he specified server and user.
     * @author Wong Kok-Lim
     */
    private Connection jdbcConnection() throws SQLException {
        String url = "jdbc:trino://192.168.232.132:8080/kudu/default";
        Properties properties = new Properties();
        properties.setProperty("user", "test");

        return DriverManager.getConnection(url, properties);
    }

    /**
     * Creates a SQL Statement from the provided JDBC connection.
     * @param con JDBC connection to use.
     * @return Statement class
     * @throws SQLException Statement can't be created with the provided JDBC connection.
     */
    private Statement getStatement(Connection con) throws SQLException {
        return con.createStatement();
    }
}
