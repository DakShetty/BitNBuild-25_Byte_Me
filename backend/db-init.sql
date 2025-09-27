INSERT INTO vendors (name,email,password_hash,address,lat,lon)
VALUES ('Demo Vendor','vendor@demo.com','$2b$10$CwTycUXWue0Thq9StjUM0u', 'Demo Address', 12.9716,77.5946)
ON CONFLICT DO NOTHING;

-- use bcrypt hash for 'password' — the hash above is not necessarily valid; better register via UI.
INSERT INTO customers (name,email,password_hash,address,lat,lon)
VALUES ('Demo Customer','cust@demo.com','$2b$10$CwTycUXWue0Thq9StjUM0u','Customer Address',12.9352,77.6245)
ON CONFLICT DO NOTHING;
