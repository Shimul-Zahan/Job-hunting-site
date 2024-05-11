import { useContext, useEffect, useState } from "react";
import { RiDeleteBin6Line } from "react-icons/ri";
import { message } from "antd";
import axios from "axios";
import { Navigate, useLocation } from "react-router";
import { AuthContext } from "../../../../providers/AuthProviders";
import Swal from "sweetalert2";

const Users = () => {
  const [users, setUsers] = useState([]);
  const { user } = useContext(AuthContext);
  const token = localStorage.getItem("access-token");
  const location = useLocation();
  const from = location.state?.from?.pathname || "/";

  useEffect(() => {
    fetchUsers();
  }, [token]);


  if (user.role !== "admin") {
    return <Navigate to={from} />;
  }
  const fetchUsers = () => {
    const url = "http://localhost:5000/users";
    fetch(url, {
      headers: {
        authorization: `bearer ${token}`,
      },
    })
      .then((res) => res.json())
      .then((data) => {
        setUsers(data);
        console.log(data);
      })
      .catch((error) => {
        console.log(error);
      });
  };

  const handleDeleteBtn = async (email) => {
    const result = await Swal.fire({
      title: "Are you sure?",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#3085d6",
      cancelButtonColor: "#d33",
      confirmButtonText: "Yes, delete it!"
    });
    if (result.isConfirmed) {
      try {
        const response = await axios.delete(`http://localhost:5000/user/delete/${email}`);
        const { data } = response;
        console.log("🚀 ~ .then ~ response:", response);
        if (data.message) {
          await Swal.fire({
            title: "Deleted!",
            text: "User deleted successfully",
            icon: "success"
          });
          fetchUsers();
        } else {
          message.error("Failed to delete user");
        }
      } 
      catch (error) {
        console.error("Error deleting user:", error);
        message.error("An error occurred while deleting user");
      }
    }
  };

  const handleMakeAdmin = (user) => {
    fetch(`http://localhost:5000/users/admin/${user._id}`, {
      method: "PATCH",
    })
      .then((res) => res.json())
      .then((data) => {
        console.log(data);
        if (data.modifiedCount) {
          // alert(`${user.name} is an admin now`);
          message.success("Role Updated!");
          setUsers((prevUsers) => {
            return prevUsers.map((prevUser) => {
              if (prevUser._id === user._id) {
                return { ...prevUser, role: "admin" };
              } else {
                return prevUser;
              }
            });
          });
        }
      });
  };

  const getBadgeClass = (role) => {
    switch (role) {
      case "admin":
        return "badge-accent";
      case "jobseeker":
        return "badge-primary";
      case "employer":
        return "badge-warning";
      default:
        return "";
    }
  };

  return (
    <div className="m-6 custom-shadow rounded-md">
      <div className="overflow-x-auto">
        <table className="table table-zebra">
          {/* head */}
          <thead>
            <tr className="text-base text-center">
              <th>No.</th>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody className="text-center">
            {users.map((user, index) => (
              <tr key={user._id}>
                <th>{index + 1}</th>
                <td className="capitalize">{user.name}</td>
                <td>{user.email}</td>
                <td>
                  <div
                    className={`badge ${getBadgeClass(
                      user.role
                    )} badge-md text-white`}
                  >
                    {user.role}
                  </div>
                </td>
                <td>
                  <div className="flex justify-center">
                    <div className="text-red-700 text-xl cursor-pointer"></div>
                    {user.role === "admin" ? (
                      <div className=" flex gap-2">
                        <button
                          className="btn btn-success btn-sm text-white w-32"
                          disabled
                        >
                          Make Admin
                        </button>
                        <button
                          className="btn btn-error btn-sm text-white w-32"
                          disabled
                        >
                          <RiDeleteBin6Line size="1.2em" />
                        </button>
                      </div>
                    ) : (
                      <div className=" flex gap-2">
                        <button
                          className="btn btn-success btn-sm text-white w-32"
                          onClick={() => handleMakeAdmin(user)}
                        >
                          Make Admin
                        </button>
                        <button
                          className="btn btn-error btn-sm text-white w-32"
                          onClick={() => handleDeleteBtn(user.email)}
                        >
                          <RiDeleteBin6Line size="1.2em" />
                        </button>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Users;
