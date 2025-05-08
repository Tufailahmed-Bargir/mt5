import MetaTrader5 as mt5
from fastapi import FastAPI, HTTPException, Query, Form, Body, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
import uvicorn
from typing import List, Dict, Any, Union, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
import pandas as pd
import jwt
import os
from uuid import uuid4

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

# User session management - store user MT5 credentials in memory
# In a production environment, you'd use a more robust storage like Redis
user_sessions = {}

# Competition models
class Competition(BaseModel):
    name: str
    description: str
    start_date: datetime
    end_date: datetime
    prize_details: str
    status: str = "upcoming"  # upcoming, active, completed

class CompetitionRegistration(BaseModel):
    user_id: str
    name: str
    email: str
    experience: str
    comments: Optional[str] = None

class CompetitionParticipant(BaseModel):
    user_id: str
    user_name: str
    mt5_account_id: str
    competition_id: str
    initial_balance: float = 10000.0
    registration_date: datetime = None

# In-memory storage for competitions and participants
# In production, you would use a database
competitions = {}
competition_participants = {}
competition_results = {}

# Connect to MetaTrader 5 with user credentials
def connect_mt5(login, password, server):
    # Initialize if not already
    if not mt5.initialize():
        error_code, error_message = mt5.last_error()
        print(f"MT5 Initialization failed: ({error_code}, {error_message})")
        raise HTTPException(status_code=500, detail=f"Failed to initialize MT5: ({error_code}, {error_message})")

    # Convert login to integer
    try:
        login_int = int(login)
    except ValueError:
        raise HTTPException(status_code=400, detail="Login ID must be a number")

    # Log in with provided credentials
    authorized = mt5.login(login_int, password=password, server=server)
    if not authorized:
        error_code, error_message = mt5.last_error()
        print(f"MT5 Login failed: ({error_code}, {error_message})")
        raise HTTPException(status_code=401, detail=f"Failed to login to MT5: ({error_code}, {error_message})")

    print(f"MT5 Login successful for account {login}")
    return True

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

# Routes
@app.get("/")
def root():
    """Root endpoint to check if API is running"""
    return {"status": "ok", "message": "MT5 API is running"}

@app.get("/api/mt5/account-info")
async def get_account_info(user: dict = Depends(get_user_session)):
    """Get MT5 account information for the authenticated user"""
    connect_mt5(user["login"], user["password"], user["server"])
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
async def get_positions(user: dict = Depends(get_user_session)):
    """Get current open positions for the authenticated user"""
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
async def get_history_deals(days: int = Query(30, ge=1, le=90), user: dict = Depends(get_user_session)):
    """Get historical deals for a specified number of days"""
    connect_mt5(user["login"], user["password"], user["server"])

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
async def get_history_orders(days: int = Query(30, ge=1, le=90), user: dict = Depends(get_user_session)):
    """Get historical orders for a specified number of days"""
    connect_mt5(user["login"], user["password"], user["server"])

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
async def get_symbols(user: dict = Depends(get_user_session)):
    """Get available symbols"""
    connect_mt5(user["login"], user["password"], user["server"])
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
async def get_ticks(symbols: str, user: dict = Depends(get_user_session)):
    """Get current ticks for multiple symbols"""
    connect_mt5(user["login"], user["password"], user["server"])

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
async def get_rates(symbol: str, timeframe: str, bars: int = Query(100, ge=10, le=500), user: dict = Depends(get_user_session)):
    """Get historical rates for a symbol and timeframe"""
    connect_mt5(user["login"], user["password"], user["server"])

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
    try:
        # Try to connect with provided credentials
        connect_mt5(request.login, request.password, request.server)
        
        # Generate a unique session ID
        session_id = str(uuid4())
        
        # Store user credentials in session
        user_sessions[session_id] = {
            "login": request.login,
            "password": request.password,
            "server": request.server
        }
        
        # Create JWT token with session ID
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
            "expires_in": ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds
        }
    except HTTPException as e:
        return {"status": "error", "message": str(e.detail)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/mt5/pnl")
async def get_pnl(cumulative: bool = Query(False), days: int = Query(30, ge=1, le=365), user: dict = Depends(get_user_session)):
    """
    Get daily net P&L or cumulative P&L for the last 'n' days.
    :param cumulative: If True, return cumulative P&L; otherwise, return daily net P&L.
    :param days: Number of days to retrieve data for.
    """
    connect_mt5(user["login"], user["password"], user["server"])

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

# Competition endpoints
@app.post("/api/competitions")
async def create_competition(competition: Competition):
    """Create a new competition"""
    competition_id = str(uuid4())
    competitions[competition_id] = {
        **competition.dict(),
        "id": competition_id, 
        "created_at": datetime.utcnow(),
        "participants_count": 0
    }
    
    # Initialize empty participants list
    competition_participants[competition_id] = []
    
    return {
        "status": "success", 
        "message": "Competition created successfully",
        "id": competition_id
    }

@app.get("/api/competitions")
async def list_competitions(status: str = None):
    """List all competitions or filter by status"""
    filtered_competitions = []
    
    for comp_id, comp in competitions.items():
        # Update competition status based on dates
        now = datetime.utcnow()
        comp_start = comp["start_date"]
        comp_end = comp["end_date"]
        
        # Auto-update status based on dates
        if now < comp_start:
            comp["status"] = "upcoming"
        elif now >= comp_start and now <= comp_end:
            comp["status"] = "active"
        elif now > comp_end:
            comp["status"] = "completed"
        
        # Apply status filter if provided
        if status is None or comp["status"] == status:
            filtered_competitions.append({
                **comp,
                "participants_count": len(competition_participants.get(comp_id, [])),
                "start_date": comp["start_date"].isoformat(),
                "end_date": comp["end_date"].isoformat()
            })
    
    return {"competitions": filtered_competitions}

@app.get("/api/competitions/{competition_id}")
async def get_competition(competition_id: str):
    """Get competition details by ID"""
    if competition_id not in competitions:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    competition = competitions[competition_id]
    participants_list = competition_participants.get(competition_id, [])
    
    return {
        **competition,
        "participants_count": len(participants_list),
        "start_date": competition["start_date"].isoformat(),
        "end_date": competition["end_date"].isoformat()
    }

@app.post("/api/competitions/{competition_id}/register")
async def register_for_competition(competition_id: str, registration: CompetitionRegistration):
    """Register a user for a competition"""
    if competition_id not in competitions:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    competition = competitions[competition_id]
    
    # Check if competition is open for registration (upcoming or active)
    if competition["status"] == "completed":
        raise HTTPException(status_code=400, detail="This competition has ended and is no longer accepting registrations")
    
    # Check if user is already registered
    if any(p["user_id"] == registration.user_id for p in competition_participants.get(competition_id, [])):
        raise HTTPException(status_code=400, detail="User is already registered for this competition")
    
    # Add participant to competition
    competition_participants.setdefault(competition_id, []).append({
        "user_id": registration.user_id,
        "user_name": registration.name,
        "email": registration.email,
        "experience": registration.experience,
        "comments": registration.comments,
        "mt5_account_id": None,  # Will be assigned by admin
        "mt5_password": None,
        "mt5_server": None,
        "registration_date": datetime.utcnow(),
        "status": "pending"  # pending, approved, rejected
    })
    
    competitions[competition_id]["participants_count"] = len(competition_participants[competition_id])
    
    return {
        "status": "success",
        "message": "Registration successful. Admin will review and provide MT5 credentials."
    }

@app.post("/api/competitions/{competition_id}/assign-account")
async def assign_account(
    competition_id: str, 
    user_id: str, 
    mt5_account: str, 
    mt5_password: str, 
    mt5_server: str
):
    """Admin endpoint to assign MT5 credentials to a participant"""
    if competition_id not in competitions:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    participants = competition_participants.get(competition_id, [])
    participant_found = False
    
    for i, participant in enumerate(participants):
        if participant["user_id"] == user_id:
            participant_found = True
            participants[i].update({
                "mt5_account_id": mt5_account,
                "mt5_password": mt5_password,
                "mt5_server": mt5_server,
                "status": "approved",
                "approved_at": datetime.utcnow()
            })
            break
    
    if not participant_found:
        raise HTTPException(status_code=404, detail="Participant not found")
    
    return {
        "status": "success",
        "message": "MT5 account credentials assigned successfully"
    }

@app.post("/api/competitions/{competition_id}/calculate-results")
async def calculate_competition_results(competition_id: str):
    """Calculate and store results for a competition"""
    if competition_id not in competitions:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    competition = competitions[competition_id]
    
    # Check if competition has ended
    now = datetime.utcnow()
    if now <= competition["end_date"]:
        raise HTTPException(status_code=400, detail="Competition is still active. Cannot calculate results yet.")
    
    participants = competition_participants.get(competition_id, [])
    if not participants:
        raise HTTPException(status_code=400, detail="No participants in this competition")
    
    # Filter out participants without MT5 accounts
    participants_with_accounts = [p for p in participants if p.get("mt5_account_id")]
    
    if not participants_with_accounts:
        raise HTTPException(status_code=400, detail="No participants with MT5 accounts found")
    
    # Calculate results for each participant
    results = []
    for participant in participants_with_accounts:
        try:
            # Connect to MT5 with participant's credentials
            connect_mt5(
                participant["mt5_account_id"],
                participant["mt5_password"],
                participant["mt5_server"]
            )
            
            # Get account info
            account_info = mt5.account_info()
            if not account_info:
                print(f"Failed to get account info for participant {participant['user_id']}")
                continue
            
            # Calculate profit based on initial balance (default 10000)
            initial_balance = participant.get("initial_balance", 10000.0)
            final_balance = account_info.balance
            profit = final_balance - initial_balance
            profit_percentage = (profit / initial_balance) * 100
            
            results.append({
                "user_id": participant["user_id"],
                "user_name": participant["user_name"],
                "mt5_account_id": participant["mt5_account_id"],
                "initial_balance": initial_balance,
                "final_balance": final_balance,
                "profit": profit,
                "profit_percentage": profit_percentage,
                "calculated_at": datetime.utcnow()
            })
            
        except Exception as e:
            print(f"Error calculating results for participant {participant['user_id']}: {str(e)}")
    
    # Sort results by profit (descending)
    results.sort(key=lambda x: x["profit"], reverse=True)
    
    # Store results
    competition_results[competition_id] = results
    
    # Update competition status
    competitions[competition_id]["status"] = "completed"
    competitions[competition_id]["results_calculated"] = True
    
    return {
        "status": "success",
        "message": "Competition results calculated successfully",
        "results": results[:10]  # Return top 10 results
    }

@app.get("/api/competitions/{competition_id}/leaderboard")
async def get_competition_leaderboard(competition_id: str):
    """Get competition leaderboard"""
    if competition_id not in competitions:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    competition = competitions[competition_id]
    
    # Check if results have been calculated
    if competition["status"] != "completed" or competition_id not in competition_results:
        raise HTTPException(status_code=400, detail="Results not yet calculated for this competition")
    
    # Get top results
    results = competition_results[competition_id]
    
    # Add rank information
    for i, result in enumerate(results):
        result["rank"] = i + 1
    
    return {
        "competition": {
            "id": competition_id,
            "name": competition["name"],
            "description": competition["description"],
            "start_date": competition["start_date"].isoformat(),
            "end_date": competition["end_date"].isoformat(),
        },
        "results": results,
        "top_winners": results[:3] if len(results) >= 3 else results
    }

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

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)