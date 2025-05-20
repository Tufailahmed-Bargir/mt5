 
import MetaTrader5 as mt5
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
import uvicorn
from typing import List
from pydantic import BaseModel
from datetime import datetime, timedelta
import pandas as pd
import jwt
import os
from uuid import uuid4

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-should-be-very-long-and-secure")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

# Initialize OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Initialize FastAPI app
app = FastAPI(title="MT5 API Server")

# Add CORS middleware to allow requests from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# User session management - store user MT5 credentials in memory
user_sessions = {}

# Connect to MetaTrader 5 with user credentials
def connect_mt5(login, password, server):
    # Initialize if not already
    try:
        import MetaTrader5 as mt5
    except ImportError:
        error_msg = "MetaTrader5 module not installed. Please install it using: pip install MetaTrader5"
        print(error_msg)
        return False, error_msg
    
    # Assuming MT5 is already running in the background, just initialize without path
    if not mt5.initialize():
        error_code, error_message = mt5.last_error()
        error_msg = f"MT5 Initialization failed: ({error_code}, {error_message})"
        print(error_msg)
        return False, error_msg

    # Convert login to integer
    try:
        login_int = int(login)
    except ValueError:
        error_msg = "Login ID must be a number"
        print(error_msg)
        return False, error_msg

    # Log in with provided credentials
    authorized = mt5.login(login_int, password=password, server=server)
    if not authorized:
        error_code, error_message = mt5.last_error()
        error_msg = f"MT5 Login failed: ({error_code}, {error_message})"
        print(error_msg)
        return False, error_msg

    print(f"MT5 Login successful for account {login}")
    return True, "Login successful"

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

# Function to verify JWT token and get user session
async def get_user_session(token: str = Depends(oauth2_scheme)):
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        session_id = payload.get("session_id")
        
        if session_id is None or session_id not in user_sessions:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        return user_sessions[session_id]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Pydantic models for the calculate-balances endpoint
class Participant(BaseModel):
    participant_id: str
    mt5_login: str
    mt5_server: str
    initial_balance: float
    password: str

class ContestData(BaseModel):
    contest_id: str
    participants: List[Participant]

# Routes
@app.get("/")
def root():
    return {"status": "ok", "message": "MT5 API is running"}

@app.get("/api/mt5/account-info")
async def get_account_info(user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])
    account_info = mt5.account_info()

    if not account_info:
        raise HTTPException(status_code=500, detail="Failed to get account info")

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
async def get_positions(user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])
    positions = mt5.positions_get()

    if positions is None:
        print("Error retrieving positions:", mt5.last_error())
        return {"error": "Failed to retrieve positions", "details": mt5.last_error()}

    if len(positions) == 0:
        print("No open positions found.")
        return []

    positions_data = []
    for position in positions:
        pos_dict = position._asdict()
        positions_data.append({
            "ticket": pos_dict.get("ticket"),
            "symbol": pos_dict.get("symbol"),
            "type": pos_dict.get("type"),
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
async def get_history_deals(days: int = 30, user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])

    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()

    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())

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
            "type": deal_dict.get("type"),
            "entry": deal_dict.get("entry"),
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
async def get_history_orders(days: int = 30, user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])

    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()

    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())

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
            "type": order_dict.get("type"),
            "state": order_dict.get("state"),
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
async def get_symbols(user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])
    symbols = mt5.symbols_get()

    if symbols is None:
        return []

    symbols_data = []
    for s in symbols:
        if not hasattr(s, 'visible') or s.visible:
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
async def get_ticks(symbols: str, user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])

    symbols_list = symbols.split(",")
    ticks_data = {}

    for symbol in symbols_list:
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
async def get_rates(symbol: str, timeframe: str, bars: int = 100, user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])

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
    try:
        success, message = connect_mt5(request.login, request.password, request.server)
        
        if not success:
            return {"status": "error", "message": message}
        
        session_id = str(uuid4())
        
        user_sessions[session_id] = {
            "login": request.login,
            "password": request.password,
            "server": request.server
        }
        
        access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
        access_token = create_jwt_token(
            data={"session_id": session_id}, 
            expires_delta=access_token_expires
        )
        
        return {
            "status": "success",
            "message": "Logged in successfully",
            "token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/mt5/pnl")
async def get_pnl(cumulative: bool = False, days: int = 30, user: dict = Depends(get_user_session)):
    connect_mt5(user["login"], user["password"], user["server"])

    from_date = datetime.now() - timedelta(days=days)
    to_date = datetime.now()

    from_timestamp = int(from_date.timestamp())
    to_timestamp = int(to_date.timestamp())

    history_deals = mt5.history_deals_get(from_timestamp, to_timestamp)

    if history_deals is None:
        raise HTTPException(status_code=500, detail="Failed to retrieve historical deals")

    daily_pnl = {}
    for deal in history_deals:
        deal_time = datetime.fromtimestamp(deal.time).date()
        if deal_time not in daily_pnl:
            daily_pnl[deal_time] = 0
        daily_pnl[deal_time] += deal.profit

    sorted_pnl = sorted(daily_pnl.items())

    response_data = []
    cumulative_pnl = 0
    for date, pnl in sorted_pnl:
        if cumulative:
            cumulative_pnl += pnl
            response_data.append({"date": date.isoformat(), "pnl": cumulative_pnl})
        else:
            response_data.append({"date": date.isoformat(), "pnl": pnl})

    return response_data

@app.post("/api/calculate-balances")
async def calculate_balances(data: ContestData):
    results = []
    
    for participant in data.participants:
        try:
            # Try to initialize and connect to MT5 for this participant
            print(f"Attempting to connect to MT5 for participant {participant.participant_id} with login {participant.mt5_login}")
            success, message = connect_mt5(participant.mt5_login, participant.password, participant.mt5_server)
            if not success:
                print(f"MT5 connection failed for participant {participant.participant_id}: {message}")
                results.append({
                    "participant_id": participant.participant_id,
                    "error": message,
                    "status": "error"
                })
                continue
            
            print(f"MT5 connection successful for participant {participant.participant_id}")
            
            # Import MT5 within the function to ensure it's accessible
            import MetaTrader5 as mt5
            
            # Only proceed if MT5 successfully initialized and logged in
            account_info = mt5.account_info()
            if account_info:
                current_balance = account_info.balance
                profit_loss = current_balance - participant.initial_balance
                print(f"Account info retrieved for {participant.participant_id}: Balance={current_balance}, Profit/Loss={profit_loss}")
                results.append({
                    "participant_id": participant.participant_id,
                    "current_balance": current_balance,
                    "profit_loss": profit_loss,
                    "status": "success"
                })
            else:
                error_code, error_message = mt5.last_error()
                error_msg = f"Failed to retrieve account info: ({error_code}, {error_message})"
                print(error_msg)
                results.append({
                    "participant_id": participant.participant_id,
                    "error": error_msg,
                    "status": "error"
                })
        except Exception as e:
            error_msg = f"Exception processing participant {participant.participant_id}: {str(e)}"
            print(error_msg)
            results.append({
                "participant_id": participant.participant_id,
                "error": error_msg,
                "status": "error"
            })
        finally:
            # Shutdown MT5 after processing each participant to ensure we start fresh for the next one
            try:
                mt5.shutdown()
                print(f"MT5 shutdown successful for participant {participant.participant_id}")
            except Exception as e:
                print(f"Error during MT5 shutdown: {str(e)}")
    
    return {
        "contest_id": data.contest_id,
        "results": results
    }

@app.on_event("startup")
async def startup_event():
    print("========================================")
    print("🚀 MT5 API Server started successfully!")
    print(f"📊 Server is now running on http://localhost:8000")
    print("📈 Ready to process trading data")
    
    # Check if MT5 is installed and can be initialized
    try:
        import MetaTrader5 as mt5
        # Try to find the MT5 terminal
        possible_paths = [
            None,  # Default (no path)
            "C:\\Program Files\\MetaTrader 5\\terminal64.exe",
            "C:\\Program Files (x86)\\MetaTrader 5\\terminal64.exe",
            f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\MetaTrader 5\\terminal64.exe",
        ]
        
        found = False
        for path in possible_paths:
            try:
                print(f"Checking MT5 path: {path}")
                initialized = False
                if path:
                    initialized = mt5.initialize(path=path)
                else:
                    initialized = mt5.initialize()
                    
                if initialized:
                    terminal_info = mt5.terminal_info()
                    if terminal_info:
                        print(f"✅ MT5 Terminal detected at: {path}")
                        print(f"   Terminal name: {terminal_info.name}")
                        print(f"   Build: {terminal_info.build}")
                        print(f"   Actual path: {terminal_info.path}")
                        found = True
                        # Success, no need to try other paths
                        break
                    else:
                        print(f"❓ MT5 initialized at {path} but terminal_info is None")
                        mt5.shutdown()
                else:
                    error_code, error_message = mt5.last_error()
                    print(f"❌ MT5 initialization failed at {path}: ({error_code}, {error_message})")
            except Exception as e:
                print(f"❌ Error checking MT5 path {path}: {str(e)}")
            finally:
                try:
                    if initialized:
                        mt5.shutdown()
                except:
                    pass
        
        if not found:
            print("❌ Could not find MetaTrader 5 terminal on this system.")
            print("   Please install MetaTrader 5 and make sure it's running.")
            print("   You may need to set the correct path in the code.")
            
    except ImportError:
        print("❌ MetaTrader5 module not installed. Install with: pip install MetaTrader5")
    except Exception as e:
        print(f"❌ MT5 check failed: {str(e)}")
    
    print("========================================")

@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down MT5 connection...")
    mt5.shutdown()
    print("MT5 connection closed.")

if __name__ == "__main__":
    uvicorn.run("app2:app", host="0.0.0.0", port=8000, reload=True)