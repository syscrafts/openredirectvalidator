#!/usr/bin/env python3
import unittest
import asyncio
from unittest.mock import AsyncMock, patch
import aiohttp
from io import StringIO
import sys
from main import fuzzify_url, load_urls, fetch_url, process_url

class TestOpenRedireX(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.url = "http://testphp.vulnweb.com/redir.php?r=FUZZ&view=FUZZ&task=FUZZ&id=FUZZ"
        self.keyword = "FUZZ"
        self.semaphore = asyncio.Semaphore(100)
        # Load payloads from payloads.txt once during setup
        self.payloads = self.load_test_payloads()

    def load_test_payloads(self):
        """Load payloads from payloads.txt for use in tests."""
        try:
            with open("payloads.txt") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback to a minimal payload list if payloads.txt is missing
            print("Warning: payloads.txt not found during tests. Using minimal fallback payloads.")
            return ["/https://google.com"]

    def test_fuzzify_url(self):
        result = fuzzify_url(self.url, self.keyword)
        self.assertEqual(result, self.url)
        
        url_no_fuzz = "http://testphp.vulnweb.com/redir.php?r=test&view=test2"
        result = fuzzify_url(url_no_fuzz, "FUZZ")
        self.assertEqual(result, "http://testphp.vulnweb.com/redir.php?r=FUZZ&view=FUZZ")

    def test_load_urls(self):
        input_data = "http://testphp.vulnweb.com/redir.php?r=FUZZ&view=FUZZ&task=FUZZ&id=FUZZ\nhttp://example.com/?q=test\n"
        with patch('sys.stdin', StringIO(input_data)):
            urls = load_urls()
            self.assertEqual(len(urls), 2)
            self.assertIn(self.url, urls)

    @patch('aiohttp.ClientSession.head')
    async def test_fetch_url_success(self, mock_head):
        mock_response = AsyncMock()
        mock_response.history = [AsyncMock(url="http://testphp.vulnweb.com/redir.php?r=test"),
                                AsyncMock(url="http://google.com")]
        mock_head.return_value.__aenter__.return_value = mock_response
        
        async with aiohttp.ClientSession() as session:
            result = await fetch_url(session, self.url)
            self.assertIsNotNone(result)
            self.assertEqual(len(result.history), 2)

    @patch('aiohttp.ClientSession.head')
    async def test_fetch_url_error(self, mock_head):
        mock_head.side_effect = aiohttp.ClientConnectorError(None, OSError("Connection error"))
        
        async with aiohttp.ClientSession() as session:
            result = await fetch_url(session, self.url)
            self.assertIsNone(result)

    @patch('aiohttp.ClientSession.head')
    async def test_process_url_redirect_found(self, mock_head):
        mock_response = AsyncMock()
        mock_response.history = [AsyncMock(url="http://testphp.vulnweb.com/redir.php?r=test"),
                                AsyncMock(url="http://google.com")]
        mock_head.return_value.__aenter__.return_value = mock_response
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            async with aiohttp.ClientSession() as session:
                pbar = MockTqdm()
                # Use the first payload from payloads.txt (or fallback)
                await process_url(self.semaphore, session, self.url, self.payloads[:1], self.keyword, pbar)
                output = fake_out.getvalue()
                self.assertIn("[FOUND]", output)
                self.assertIn("redirects to", output)

    @patch('aiohttp.ClientSession.head')
    async def test_process_url_no_redirect(self, mock_head):
        mock_response = AsyncMock()
        mock_response.history = []
        mock_head.return_value.__aenter__.return_value = mock_response
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            async with aiohttp.ClientSession() as session:
                pbar = MockTqdm()
                # Use the first payload from payloads.txt (or fallback)
                await process_url(self.semaphore, session, self.url, self.payloads[:1], self.keyword, pbar)
                output = fake_out.getvalue()
                self.assertEqual(output, "")

# Custom mock class to simulate tqdm's update method without async issues
class MockTqdm:
    def update(self):
        pass

if __name__ == '__main__':
    unittest.main()
