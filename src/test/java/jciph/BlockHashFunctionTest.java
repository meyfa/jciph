package jciph;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

import de.jangobrick.jciph.hashing.BlockHashFunction;


public class BlockHashFunctionTest
{
    private static class MockBlockHashFunction extends BlockHashFunction
    {
        private LinkedList<String> calls = new LinkedList<>();
        private ByteArrayOutputStream processed = new ByteArrayOutputStream();

        public MockBlockHashFunction()
        {
            super(10);
        }

        @Override
        public void reset()
        {
            calls.add("reset");
            super.reset();
        }

        @Override
        public void digest(byte[] partialMessage)
        {
            calls.add("digest");
            super.digest(partialMessage);
        }

        @Override
        public byte[] finish()
        {
            calls.add("finish");
            return super.finish();
        }

        @Override
        protected void processBlock(byte[] block)
        {
            try {
                processed.write(block);
            } catch (IOException e) {
            }
        }

        @Override
        protected byte[] finish(byte[] remainder, int length)
        {
            calls.add("finish2");
            return null;
        }
    }

    @Test
    public void testHashCallsResetFirst()
    {
        MockBlockHashFunction mock = new MockBlockHashFunction();
        mock.hash(new byte[0]);

        assertEquals("reset", mock.calls.getFirst());
    }

    @Test
    public void testFinishCallsProtectedFinish()
    {
        MockBlockHashFunction mock = new MockBlockHashFunction();
        mock.finish();

        assertEquals("finish2", mock.calls.get(1));
    }

    @Test
    public void testFinishCallsReset()
    {
        MockBlockHashFunction mock = new MockBlockHashFunction();
        mock.finish();

        assertEquals("reset", mock.calls.getLast());
    }

    @Test
    public void testDigestProcessesMostPossible()
    {
        MockBlockHashFunction mock = new MockBlockHashFunction();
        mock.digest(new byte[32]);

        assertEquals(30, mock.processed.size());
    }

    @Test
    public void testDigestBuffersUnprocessedBytes()
    {
        MockBlockHashFunction mock = new MockBlockHashFunction();

        // set overflowing bytes to special values
        byte[] b = new byte[32];
        b[30] = 42;
        b[31] = 64;
        mock.digest(b);

        mock.digest(new byte[8]);

        assertEquals(40, mock.processed.size());

        // check for special values to exist
        byte[] proc = mock.processed.toByteArray();
        assertEquals(42, proc[30]);
        assertEquals(64, proc[31]);
    }
}
