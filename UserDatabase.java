import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

// CWE-89  (SQL Injection): every query below is a PreparedStatement with
// positional '?' placeholders. No user-controlled string is ever
// concatenated into a SQL string.
//
// CWE-312 (Cleartext Storage of Sensitive Information): the account
// balance is sensitive financial data, so it is persisted as AES-GCM
// ciphertext via EncryptionService rather than as plain integers.
//
// NOTE: requires sqlite-jdbc on the classpath — see README.md.
public class UserDatabase implements AutoCloseable {
    private final Connection conn;
    private final EncryptionService crypto;

    public UserDatabase(EncryptionService crypto) throws SQLException {
        this.crypto = crypto;
        this.conn = DriverManager.getConnection("jdbc:sqlite:slotmachine.db");
        initSchema();
    }

    private void initSchema() throws SQLException {
        try (Statement s = conn.createStatement()) {
            s.execute(
                "CREATE TABLE IF NOT EXISTS users (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  username TEXT UNIQUE NOT NULL," +
                "  password_hash TEXT NOT NULL," +
                "  balance_enc TEXT NOT NULL" +
                ")");
            s.execute(
                "CREATE TABLE IF NOT EXISTS spin_history (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  user_id INTEGER NOT NULL," +
                "  stake INTEGER NOT NULL," +
                "  winnings INTEGER NOT NULL," +
                "  ts TEXT DEFAULT CURRENT_TIMESTAMP," +
                "  FOREIGN KEY(user_id) REFERENCES users(id)" +
                ")");
        }
    }

    // CWE-89: username comes from the user, but is bound to '?' — the DB
    // driver handles escaping, so "' OR '1'='1" is treated as a literal
    // username, not as SQL syntax.
    public Integer findUserId(String username, String passwordHash) {
        String sql = "SELECT id FROM users WHERE username = ? AND password_hash = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, passwordHash);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt("id") : null;
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
            return null;
        }
    }

    public void createUser(String username, String passwordHash, int initialBalance) {
        String sql = "INSERT INTO users(username, password_hash, balance_enc) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, passwordHash);
            // CWE-312: balance is written encrypted, never in cleartext.
            ps.setString(3, crypto.encrypt(String.valueOf(initialBalance)));
            ps.executeUpdate();
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
        }
    }

    public int getBalance(int userId) {
        String sql = "SELECT balance_enc FROM users WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Integer.parseInt(crypto.decrypt(rs.getString("balance_enc")));
                }
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, String.valueOf(userId), e.getMessage());
        }
        return 0;
    }

    public void updateBalance(int userId, int newBalance) {
        String sql = "UPDATE users SET balance_enc = ? WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, crypto.encrypt(String.valueOf(newBalance)));
            ps.setInt(2, userId);
            ps.executeUpdate();
            SecurityLogger.log(SecurityLogger.Event.BALANCE_UPDATE,
                    String.valueOf(userId), "new=" + newBalance);
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, String.valueOf(userId), e.getMessage());
        }
    }

    public void recordSpin(int userId, int stake, int winnings) {
        String sql = "INSERT INTO spin_history(user_id, stake, winnings) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, userId);
            ps.setInt(2, stake);
            ps.setInt(3, winnings);
            ps.executeUpdate();
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, String.valueOf(userId), e.getMessage());
        }
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }
}
