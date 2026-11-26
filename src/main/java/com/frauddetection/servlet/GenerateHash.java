
import org.mindrot.jbcrypt.BCrypt;

public class GenerateHash {
    public static void main(String[] args) {
        String password = "RadarAdmin@123";

        String hash = BCrypt.hashpw(
            password,
            BCrypt.gensalt(12)
        );

        System.out.println(hash);
    }
}
