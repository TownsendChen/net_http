echo "1. Testing public area (should work)..."
curl -s http://localhost:8080/public/ | grep -q "Public Area"
if [ $? -eq 0 ]; then
    echo "✓ PASS: Can access public area"
else
    echo "✗ FAIL: Cannot access public area"
fi

echo "2. Testing restricted area from localhost (should work)..."
curl -s http://localhost:8080/restricted/ | grep -q "Restricted Area"
if [ $? -eq 0 ]; then
    echo "✓ PASS: Localhost can access restricted area"
else
    echo "✗ FAIL: Localhost cannot access restricted area"
fi

echo "3. Testing admin area from localhost (should work)..."
curl -s http://localhost:8080/admin/ | grep -q "Admin Area"
if [ $? -eq 0 ]; then
    echo "✓ PASS: Localhost can access admin area"
else
    echo "✗ FAIL: Localhost cannot access admin area"
fi

echo "4. Testing home page without .htaccess (should work)..."
curl -s http://localhost:8080/ | grep -q "Home Page"
if [ $? -eq 0 ]; then
    echo "✓ PASS: Can access home page"
else
    echo "✗ FAIL: Cannot access home page"
fi