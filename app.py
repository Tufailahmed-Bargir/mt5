import MetaTrader5 as mt5
from fastapi import FastAPI, HTTPException, Query, Form, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
import uvicorn
from typing import List, Dict, Any, Union, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
import pandas as pd
import jwt
import os
 

 

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-should-be-very-long-and-secure")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7  # Token valid for 1 week

# Initialize OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Initialize FastAPI app
app = FastAPI(title="MT5 API Server")

# Add CORS middleware to allow requests from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# MT5 connection parameters
MT5_ACCOUNT = 79697927
MT5_PASSWORD = "Tufail@12345"
MT5_SERVER = "Exness-MT5Trial8"

# Connect to MetaTrader 5
def connect_mt5():
    # First check if MT5 is already initialized and shut it down if needed
    if mt5.initialize():
        mt5.shutdown()
    
    # Initialize with timeout parameter
    if not mt5.initialize(timeout=60000):  # 60 seconds timeout
        error_code, error_message = mt5.last_error()
        print(f"MT5 Initialization failed: ({error_code}, {error_message})")
        raise HTTPException(status_code=500, detail=f"Failed to initialize MT5: ({error_code}, {error_message})")

    # Convert login to integer and use explicit parameter names
    try:
        # Using global variables here
        account = int(MT5_ACCOUNT)
        authorized = mt5.login(
            login=account,
            password=MT5_PASSWORD,
            server=MT5_SERVER,
            timeout=60000
        )
        
        if not authorized:
            error_code, error_message = mt5.last_error()
            print(f"MT5 Login failed: ({error_code}, {error_message})")
            raise HTTPException(status_code=401, detail=f"Failed to login to MT5: ({error_code}, {error_message})")
    
        print("MT5 Login successful")
        return True
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid login format - must be an integer")

# Function to create JWT token
def create_jwt_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to verify JWT token
async def verify_token(token: str = Depends(oauth2_scheme)):
    if token is None:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login = payload.get("sub")
        if login is None:
            return None
        return payload
    except jwt.PyJWTError:
        return None

# Routes
@app.get("/")
def root():
    """Root endpoint to check if API is running"""
    return {"status": "ok", "message": "MT5 API is running"}

@app.get("/api/mt5/account-info")
def get_account_info():
    """Get MT5 account information"""
    connect_mt5()
    account_info = mt5.account_info()
    
    if not account_info:
        raise HTTPException(status_code=500, detail="Failed to get account info")
    
    # Convert to dict
    info = account_info._asdict()
    return {
        "balance": info.get("balance"),
        "equity": info.get("equity"),
        "margin": info.get("margin"),
        "margin_free": info.get("margin_free"),
        "margin_level": info.get("margin_level"),
        "profit": info.get("profit"),
        "leverage": info.get("leverage"),
        "currency": info.get("currency"),
        "server": info.get("server"),
        "name": info.get("name")
    }

@app.get("/api/mt5/positions")
def get_positions():
    """Get current open positions"""
    connect_mt5()
    positions = mt5.positions_get()

    if positions is None:
        print("Error retrieving positions:", mt5.last_error())
        return {"error": "Failed to retrieve positions", "details": mt5.last_error()}

    if len(positions) == 0:
        print("No open positions found.")
        return {"message": "No open positions found."}

    positions_data = []
    for position in positions:
        pos_dict = position._asdict()
        positions_data.append({
            "ticket": pos_dict.get("ticket"),
            "symbol": pos_dict.get("symbol"),
            "type": pos_dict.get("type"),  # 0 for Buy, 1 for Sell
            "volume": pos_dict.get("volume"),
            "price_open": pos_dict.get("price_open"),
            "price_current": pos_dict.get("price_current"),
            "sl": pos_dict.get("sl"),
            "tp": pos_dict.get("tp"),
            "profit": pos_dict.get("profit"),
            "swap": pos_dict.get("swap"),
            "time": datetime.fromtimestamp(pos_dict.get("time", 0)).isoformat() if "time" in pos_dict else None
        })

    return positions_data

@app.get("/api/mt5/history-deals")
def get_history_deals(days: int = Query(30, ge=1, le=90)):
    """Get historical deals for a specified number of days"""
    connect_mt5()
    
    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()
    
    # Convert datetime to timestamp
    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())
    
    # Get history deals
    history_deals = mt5.history_deals_get(from_timestamp, to_timestamp)
    
    if history_deals is None:
        return []
    
    deals_data = []
    for deal in history_deals:
        deal_dict = deal._asdict()
        deals_data.append({
            "ticket": deal_dict.get("ticket"),
            "order": deal_dict.get("order"),
            "time": datetime.fromtimestamp(deal_dict.get("time", 0)).isoformat() if "time" in deal_dict else None,
            "type": deal_dict.get("type"),  # 0 Buy, 1 Sell
            "entry": deal_dict.get("entry"),  # 0 In, 1 Out, 2 In/Out
            "magic": deal_dict.get("magic"),
            "position_id": deal_dict.get("position_id"),
            "reason": deal_dict.get("reason"),
            "volume": deal_dict.get("volume"),
            "price": deal_dict.get("price"),
            "commission": deal_dict.get("commission"),
            "swap": deal_dict.get("swap"),
            "profit": deal_dict.get("profit"),
            "fee": deal_dict.get("fee"),
            "symbol": deal_dict.get("symbol"),
            "comment": deal_dict.get("comment"),
            "external_id": deal_dict.get("external_id")
        })
    
    return deals_data

@app.get("/api/mt5/history-orders")
def get_history_orders(days: int = Query(30, ge=1, le=90)):
    """Get historical orders for a specified number of days"""
    connect_mt5()
    
    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()
    
    # Convert datetime to timestamp
    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())
    
    # Get history orders
    history_orders = mt5.history_orders_get(from_timestamp, to_timestamp)
    
    if history_orders is None:
        return []
    
    orders_data = []
    for order in history_orders:
        order_dict = order._asdict()
        orders_data.append({
            "ticket": order_dict.get("ticket"),
            "time_setup": datetime.fromtimestamp(order_dict.get("time_setup", 0)).isoformat() if "time_setup" in order_dict else None,
            "time_done": datetime.fromtimestamp(order_dict.get("time_done", 0)).isoformat() if "time_done" in order_dict else None,
            "type": order_dict.get("type"),  # Order type
            "state": order_dict.get("state"),  # Order state
            "magic": order_dict.get("magic"),
            "position_id": order_dict.get("position_id"),
            "position_by_id": order_dict.get("position_by_id"),
            "reason": order_dict.get("reason"),
            "volume_initial": order_dict.get("volume_initial"),
            "volume_current": order_dict.get("volume_current"),
            "price_open": order_dict.get("price_open"),
            "sl": order_dict.get("sl"),
            "tp": order_dict.get("tp"),
            "price_current": order_dict.get("price_current"),
            "price_stoplimit": order_dict.get("price_stoplimit"),
            "symbol": order_dict.get("symbol"),
            "comment": order_dict.get("comment"),
            "external_id": order_dict.get("external_id")
        })
    
    return orders_data

@app.get("/api/mt5/symbols")
def get_symbols():
    """Get available symbols"""
    connect_mt5()
    symbols = mt5.symbols_get()
    
    if symbols is None:
        return []
    
    symbols_data = []
    for s in symbols:
        if not hasattr(s, 'visible') or s.visible:  # Only return visible symbols
            sym_dict = s._asdict()
            symbols_data.append({
                "name": sym_dict.get("name"),
                "description": sym_dict.get("description"),
                "currency_base": sym_dict.get("currency_base"),
                "currency_profit": sym_dict.get("currency_profit"),
                "spread": sym_dict.get("spread"),
                "digits": sym_dict.get("digits"),
                "visible": sym_dict.get("visible", True),
                "path": sym_dict.get("path")
            })
    
    return symbols_data

@app.get("/api/mt5/ticks")
def get_ticks(symbols: str):
    """Get current ticks for multiple symbols"""
    connect_mt5()

    symbols_list = symbols.split(",")
    ticks_data = {}

    for symbol in symbols_list:
        # Ensure the symbol is subscribed
        if not mt5.symbol_select(symbol, True):
            print(f"Failed to subscribe to symbol: {symbol}")
            continue

        tick = mt5.symbol_info_tick(symbol)
        if tick:
            tick_dict = tick._asdict()
            ticks_data[symbol] = {
                "bid": tick_dict.get("bid"),
                "ask": tick_dict.get("ask"),
                "last": tick_dict.get("last"),
                "volume": tick_dict.get("volume"),
                "time": datetime.fromtimestamp(tick_dict.get("time", 0)).isoformat() if "time" in tick_dict else None,
                "flags": tick_dict.get("flags"),
            }
        else:
            print(f"No tick data available for symbol: {symbol}")

    return ticks_data

@app.get("/api/mt5/rates")
def get_rates(symbol: str, timeframe: str, bars: int = Query(100, ge=10, le=500)):
    """Get historical rates for a symbol and timeframe"""
    connect_mt5()

    # Map timeframe string to MT5 timeframe constant
    tf_map = {
        "M1": mt5.TIMEFRAME_M1,
        "M5": mt5.TIMEFRAME_M5,
        "M15": mt5.TIMEFRAME_M15,
        "M30": mt5.TIMEFRAME_M30,
        "H1": mt5.TIMEFRAME_H1,
        "H4": mt5.TIMEFRAME_H4,
        "D1": mt5.TIMEFRAME_D1,
        "W1": mt5.TIMEFRAME_W1
    }

    if timeframe not in tf_map:
        raise HTTPException(status_code=400, detail=f"Invalid timeframe: {timeframe}. Valid options: {list(tf_map.keys())}")

    rates = mt5.copy_rates_from(symbol, tf_map[timeframe], datetime.now(), bars)

    if rates is None or len(rates) == 0:
        return []

    # Convert NumPy array to pandas DataFrame and then to dict with native Python types
    df = pd.DataFrame(rates)

    rates_data = []
    for _, row in df.iterrows():
        rates_data.append({
            "time": datetime.fromtimestamp(int(row["time"])).isoformat(),
            "open": float(row["open"]),
            "high": float(row["high"]),
            "low": float(row["low"]),
            "close": float(row["close"]),
            "tick_volume": int(row["tick_volume"]),
            "spread": int(row["spread"]),
            "real_volume": int(row["real_volume"])
        })

    return rates_data

class LoginRequest(BaseModel):
    login: str
    password: str
    server: str

@app.post("/api/login")
def login(request: LoginRequest):
    global MT5_ACCOUNT, MT5_PASSWORD, MT5_SERVER
    # Convert login string to integer
    MT5_ACCOUNT = int(request.login)
    MT5_PASSWORD = request.password
    MT5_SERVER = request.server
    try:
        connect_mt5()
        # Create JWT token
        access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
        user_data = {"sub": request.login, "server": request.server}
        access_token = create_jwt_token(
            data=user_data, expires_delta=access_token_expires
        )
        return {
            "status": "success", 
            "message": "Logged in successfully",
            "token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds
        }
    except HTTPException as e:
        return {"status": "error", "message": str(e.detail)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.on_event("startup")
async def startup_event():
    print("========================================")
    print("🚀 MT5 API Server started successfully!")
    print(f"📊 Server is now running on http://localhost:8000")
    print("📈 Ready to process trading data")
    print("========================================")

@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down MT5 connection...")
    mt5.shutdown()
    print("MT5 connection closed.")


@app.get("/api/mt5/pnl")
def get_pnl(cumulative: bool = Query(False), days: int = Query(30, ge=1, le=365)):
    """
    Get daily net P&L or cumulative P&L for the last 'n' days.
    :param cumulative: If True, return cumulative P&L; otherwise, return daily net P&L.
    :param days: Number of days to retrieve data for.
    """
    connect_mt5()
    
    # Define the time range
    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()
    
    # Convert datetime to timestamp
    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())
    
    # Get historical deals
    history_deals = mt5.history_deals_get(from_timestamp, to_timestamp)
    
    if history_deals is None:
        raise HTTPException(status_code=500, detail="Failed to retrieve historical deals")
    
    # Group deals by day and calculate daily P&L
    daily_pnl = {}
    for deal in history_deals:
        deal_time = datetime.fromtimestamp(deal.time).date()  # Get the date of the deal
        if deal_time not in daily_pnl:
            daily_pnl[deal_time] = 0
        daily_pnl[deal_time] += deal.profit  # Sum up the profit for the day
    
    # Sort by date
    sorted_pnl = sorted(daily_pnl.items())
    
    # Prepare the response data
    response_data = []
    cumulative_pnl = 0
    for date, pnl in sorted_pnl:
        if cumulative:
            cumulative_pnl += pnl
            response_data.append({"date": date.isoformat(), "pnl": cumulative_pnl})
        else:
            response_data.append({"date": date.isoformat(), "pnl": pnl})
    
    return response_data
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
