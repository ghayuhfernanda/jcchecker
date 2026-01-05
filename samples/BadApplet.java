package samples;

import java.io.*; // should be flagged

public class BadApplet {
    // synchronized method should be flagged
    public synchronized void foo() {
        double d = 1.23; // float/double usage flagged
        System.out.println("Hello"); // System.out flagged (warning)
    }

    // finalize method should be flagged
    protected void finalize() {
    }

    public void bar() {
        synchronized(this) { // synchronized block flagged
            Float f = 1.0f; // wrapper Float flagged
        }
        try {
            Class.forName("com.example.Some"); // reflection flagged
            Object o = this.getClass().newInstance(); // reflection flagged
        } catch (Exception e) {}
    }
}