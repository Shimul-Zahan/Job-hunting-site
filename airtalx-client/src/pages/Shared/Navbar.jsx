import { useContext } from "react";
import { Link } from "react-router-dom";
import { AuthContext } from "../../providers/AuthProviders";
import Spinner from "./Spinner";
import { FaAngleDown } from "react-icons/fa";

const Navbar = () => {
  const { user, logOut, loading } = useContext(AuthContext);

  if (loading) {
    return <Spinner />;
  }

  const handleLogOut = () => {
    logOut()
      .then(() => {})
      .catch((error) => console.log(error));
  };

  return (
    <div className="bg-[#edf7f4] fixed w-full z-10 mb-20">
      <div className="w-3/4 mx-auto hidden lg:block py-4">
        <div className="flex items-center justify-between">
          <Link className="w-[60px] flex items-center">
            <img className="rounded-full" src="/logo.png" alt="" />
            <h3 className="text-3xl font-semibold">airTalX</h3>
          </Link>
          <div className="flex flex-row gap-8 font-semibold">
            <Link>Home</Link>
            {user && user.role === "jobseeker" && (
              <Link to={"/jobseeker/dashboard"}>Dashboard</Link>
            )}
            {user && user.role === "employer" && (
              <Link to={"/employer/dashboard"}>Dashboard</Link>
            )}
            {user && user.role === "admin" && (
              <Link to={"/admin/dashboard"}>Dashboard</Link>
            )}
            <Link to={"/findJob"}>Find Job</Link>
            <Link to={"/findEmployee"}>Find Employee</Link>
            {/* <Link to={"/blogs"}>Blogs</Link> */}
          </div>
          <div>
            {user ? (
              <div className="dropdown pt-1 dropdown-end">
                <div
                  tabIndex={0}
                  className="flex cursor-pointer gap-2 bg-[#2792a8] rounded-full pl-3 pr-1 py-1 items-center"
                >
                  <p className="text-white font-semibold capitalize">
                    {user?.name}
                  </p>
                  <label className="btn btn-ghost btn-circle avatar">
                    <div className="rounded-full border-2 border-white">
                      {loading ? (
                        <p>Loading...</p>
                      ) : (
                        <div>
                          <img src={user?.photoURL} alt="User Photo" />
                        </div>
                      )}
                    </div>
                  </label>
                  <FaAngleDown className="absolute right-1 bottom-0 bg-white rounded-full border border-black" />
                </div>
                <ul
                  tabIndex={0}
                  className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52"
                >
                  <li>
                    <Link to="/profile" className="justify-between">
                      <div className="flex items-center gap-2">
                        {/* <CgProfile className="text-lg" /> */}
                        <p>Profile</p>
                      </div>
                    </Link>
                  </li>
                  <li>
                    <div
                      onClick={handleLogOut}
                      className="flex items-center gap-2"
                    >
                      {/* <FiLogOut className="text-lg" /> */}
                      <p>Logout</p>
                    </div>
                  </li>
                </ul>
              </div>
            ) : (
              <div className="flex gap-4 font-semibold navbar-end">
                <Link to={"/login"}>
                  <button>Login</button>
                </Link>
                <Link to={"/signup"}>
                  <button className="bg-[#1d9cb5] text-white rounded px-2 py-1">
                    Signup
                  </button>
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="bg-[#edf7f4] lg:hidden block">
        <div className="navbar flex items-center justify-between">
          <div className="navbar-start">
            <div className="dropdown">
              <div
                tabIndex={0}
                role="button"
                className="btn btn-ghost btn-circle"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M4 6h16M4 12h16M4 18h7"
                  />
                </svg>
              </div>

              <div
                tabIndex={0}
                className="menu menu-sm dropdown-content font-semibold mt-3 z-10 p-2 shadow bg-base-100 rounded-box w-52"
              >
                <Link>Home</Link>
                {user && user.role === "jobseeker" && (
                  <Link to={"/jobseeker/dashboard"}>Dashboard</Link>
                )}
                {user && user.role === "employer" && (
                  <Link to={"/employer/dashboard"}>Dashboard</Link>
                )}
                {user && user.role === "admin" && (
                  <Link to={"/admin/dashboard"}>Dashboard</Link>
                )}
                <Link to={"/findJob"}>Find Job</Link>
                <Link to={"/findEmployee"}>Find Employee</Link>
                {/* <Link to={"/blogs"}>Blogs</Link> */}
              </div>
            </div>
            <div className="w-[60px] flex items-center">
              <img className="rounded-full" src="/logo.png" alt="" />
              <h3 className="text-2xl font-semibold">airTalX</h3>
            </div>
          </div>
          {user ? (
            <div className="dropdown pt-1 dropdown-end">
              <div
                tabIndex={0}
                className="flex cursor-pointer gap-2 bg-[#2792a8] rounded-full pl-3 pr-1 py-1 items-center"
              >
                <p className="text-white font-semibold capitalize">
                  {user?.name}
                </p>
                <label className="btn btn-ghost btn-circle avatar">
                  <div className="rounded-full border-2 border-white">
                    {loading ? (
                      <p>Loading...</p>
                    ) : (
                      <div>
                        <img src={user?.photoURL} alt="User Photo" />
                      </div>
                    )}
                  </div>
                </label>
                <FaAngleDown className="absolute right-1 bottom-0 bg-white rounded-full border border-black" />
              </div>
              <ul
                tabIndex={0}
                className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52"
              >
                <li>
                  <Link to="/profile" className="justify-between">
                    <div className="flex items-center gap-2">
                      {/* <CgProfile className="text-lg" /> */}
                      <p>Profile</p>
                    </div>
                  </Link>
                </li>
                <li>
                  <div
                    onClick={handleLogOut}
                    className="flex items-center gap-2"
                  >
                    {/* <FiLogOut className="text-lg" /> */}
                    <p>Logout</p>
                  </div>
                </li>
              </ul>
            </div>
          ) : (
            <div className="flex gap-4 font-semibold navbar-end">
              <Link to={"/login"}>
                <button>Login</button>
              </Link>
              <Link to={"/signup"}>
                <button className="bg-[#1d9cb5] text-white rounded px-2 py-1">
                  Signup
                </button>
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Navbar;
