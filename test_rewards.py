import sqlite3
import unittest
import rewards

class RewardTests(unittest.TestCase):
    def test_currency_conversion_unknown_and_closed(self):
        c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;rewards.init(c)
        c.execute('UPDATE reward_fx SET day=?,rates=?',('2026-09-24','{"EUR":1,"USD":1.2,"INR":100}'))
        rows=[dict(name=n,maximum=m,currency=k,available=a) for n,m,k,a in [('Euro',15000,'EUR',1),('Dollar',17000,'USD',1),('Rupee',500000,'INR',1),('Unknown',None,'',1),('Closed',1000000,'USD',0)]]
        rewards.rank(c,rows)
        self.assertEqual([p['name'] for p in rows],['Euro','Dollar','Rupee','Unknown','Closed'])
        self.assertEqual(rows[0]['reward_usd'],18000)
        self.assertIsNone(rows[3]['reward_usd'])
    def test_missing_rates_and_invalid_feed(self):
        c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;rewards.init(c)
        p=dict(name='Euro',maximum=15000,currency='EUR',available=1)
        rewards.rank(c,[p]);self.assertIsNone(p['reward_usd']);self.assertEqual(p['reward_group'],'Exchange rate unavailable')
        with self.assertRaises(ValueError):rewards.parse(b'<root><Cube time="2026-09-24"/><Cube currency="USD" rate="NaN"/></root>')
        day,rates=rewards.parse(b'<root><Cube time="2026-09-24"/><Cube currency="USD" rate="1.2"/></root>')
        self.assertEqual(rates,{'EUR':1,'USD':1.2})
