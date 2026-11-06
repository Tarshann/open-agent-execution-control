import java.nio.file.*;

class Cleanup {
    static void wipe(Path p) throws Exception { Files.delete(p); }
}
