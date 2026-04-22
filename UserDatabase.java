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
// balance and security question answers are persisted as AES-GCM
// ciphertext via EncryptionService rather than as plaintext.
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
            // Create tables with base schema if they don't exist.
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

            addColumnIfMissing(s, "users", "security_questions",    "TEXT");
            addColumnIfMissing(s, "users", "security_answers_enc",  "TEXT");
        }
    }

    /**
     * Attempts to add a column to a table. Silently ignores the error if the
     * column already exists.
     */
    private void addColumnIfMissing(Statement s, String table, String column, String type) {
        try {
            s.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + type);
        } catch (SQLException e) {
            if (!e.getMessage().toLowerCase().contains("duplicate column name")) {
                throw new RuntimeException("Schema migration failed for column: " + column, e);
            }
        }
    }

    public Integer findUserId(String username, String passwordHash) {
        // CWE-233: Improper Handline of Parameters - reject null parameters before trying to use them
        if (username == null || passwordHash == null) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, "(null)", "null parameter passed to findUserId");
            return null;
        }

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

    public boolean usernameExists(String username) {
        String sql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
            return false;
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
        // CWE-229: Improper Handling of Values - reject balance values outside a valid range
        if (newBalance < 0 || newBalance > 1000000) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, String.valueOf(userId), "balance out of range: " + newBalance);
            return;
        }

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
        // CWE-233: Improper Handling of Parameters - reject invalid stake and winnings values before trying to use them
        if (stake <= 0 || winnings < 0) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, String.valueOf(userId), "invalid stake or winnings: stake=" + stake + "winnings: " + winnings);
            return;
        }

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

    /**
     * Returns the stored password hash for a given username, or null if the
     * user does not exist. Used by UserAccountService to load credentials
     * before delegating to PasswordManager.
     */
    public String getPasswordHash(String username) {
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("password_hash") : null;
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
            return null;
        }
    }

    /**
     * Updates the password hash for a given username. Called after a
     * successful PasswordManager.resetPassword() flow so the new hash is
     * persisted to the database.
     */
    public void updatePasswordHash(String username, String newHash) {
        String sql = "UPDATE users SET password_hash = ? WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, newHash);
            ps.setString(2, username);
            ps.executeUpdate();
            SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "password hash updated");
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
        }
    }


    /**
     * Returns the security questions for a given username as a String array,
     * or null if none are stored. Questions are stored plaintext — only answers
     * are sensitive and encrypted.
     */
    public String[] getSecurityQuestions(String username) {
        String sql = "SELECT security_questions FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String raw = rs.getString("security_questions");
                    return raw != null ? raw.split("\\|", -1) : null;
                }
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
        }
        return null;
    }

    /**
     * Returns the decrypted security answers for a given username as a String
     * array, or null if none are stored.
     * CWE-312: answers are stored encrypted and decrypted on retrieval.
     */
    public String[] getSecurityAnswers(String username) {
        String sql = "SELECT security_answers_enc FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String enc = rs.getString("security_answers_enc");
                    if (enc == null) return null;
                    String decrypted = crypto.decrypt(enc);
                    return decrypted.split("\\|", -1);
                }
            }
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
        }
        return null;
    }

    /**
     * Persists security questions and encrypted answers for a given username.
     * Called during registration (after PasswordManager collects them) and
     * optionally after a successful password reset.
     * CWE-312: answers are encrypted before storage.
     *
     * @param username  the account to update
     * @param questions plaintext questions (stored as-is)
     * @param answers   plaintext answers (encrypted before write)
     */
    public void updateSecurityQA(String username, String[] questions, String[] answers) {
        String joinedQuestions = String.join("|", questions);
        String joinedAnswers   = String.join("|", answers);
        String sql = "UPDATE users SET security_questions = ?, security_answers_enc = ? WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, joinedQuestions);
            ps.setString(2, crypto.encrypt(joinedAnswers));
            ps.setString(3, username);
            ps.executeUpdate();
        } catch (SQLException e) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, e.getMessage());
        }
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }
}