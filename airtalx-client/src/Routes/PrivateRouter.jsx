import { useContext } from "react";
import { Navigate, useLocation } from "react-router";
import { AuthContext } from "../providers/AuthProviders";
import Spinner from "../pages/Shared/Spinner";

const PrivateRouter = ({ children }) => {
    const { user,loading } = useContext(AuthContext);
    const location = useLocation();
    const from = location.state?.from?.pathname || "/";

    if (loading) {
        return <Spinner />;
    }

    if (user && !loading) {
        return children;
    }
    return <Navigate to="/login" state={from} replace></Navigate>
};

export default PrivateRouter;